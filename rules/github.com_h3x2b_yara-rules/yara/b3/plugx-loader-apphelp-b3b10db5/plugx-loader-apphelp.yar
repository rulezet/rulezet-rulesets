import "pe"
rule plugx_loader_apphelp : APT
{
    meta:
        description = "Identify the PlugX side loader used to trojan legit software like KMPlayer"
        author = "@h3x2b <tracker _AT h3x.eu>"

    strings:
        $yes_s1 = "RtlUnwind"
        $yes_s2 = "LoadLibraryA"
        $no_s1 = "ApphelpUpdateCacheEntry"

    condition:
                uint16(0) == 0x5a4d
        and pe.characteristics & pe.DLL

        and all of ( $yes_* )
        and not $no_s1

        }