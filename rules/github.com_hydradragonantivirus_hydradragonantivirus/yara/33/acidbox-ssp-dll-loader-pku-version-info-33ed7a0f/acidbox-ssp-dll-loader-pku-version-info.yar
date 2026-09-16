import "pe"
rule AcidBox_SSP_DLL_Loader_pku_Version_Info {
  meta:
    description = "Detects AcidBox SSP DLL loaders, based on a unique version information of 'pku.dll'"
    author      = "BitsOfBinary"
    reference   = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
    reference   = "https://bitsofbinary.github.io/yara/2023/03/25/100daysofyara-day-84.html"
    version     = "1.0"
    date        = "2023-03-24"
    DaysofYARA  = "84/100"

  condition:
    pe.version_info["InternalName"] == "pku.dll"
}