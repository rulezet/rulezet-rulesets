rule SUSP_LNX_ARCH_SRCINFO_NPM_Dependency_Jun26_RID3539: DEMO LINUX SCRIPT SUSP {
  meta:
    description = "Detects suspicious .SRCINFO with NPM dependency and install script"
    author      = "Marius Benthin"
    reference   = "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency"
    date        = "2026-06-15 16:04:01"
    score       = 60
    customer    = "demo"
    license     = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"

    tags         = "DEMO, LINUX, SCRIPT, SUSP"
    minimum_yara = "3.5.0"

  strings:
    $s1 = "depends = npm\n"
    $s2 = { 69 6E 73 74 61 6C 6C 20 3D 20 [1-50] 2E 69 6E 73 74 61 6C 6C }

  condition:
    filesize < 5KB and all of them
}