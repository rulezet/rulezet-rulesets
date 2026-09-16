import "pe"
rule MAL_Zardoor_Dropper_Resource_TypeString_CODER {
  meta:
    author      = "Greg Lesnewich"
    description = "look for weird typestring included in Zardoor loader called CODER"
    date        = "2024-02-12"
    version     = "1.0"
    reference   = "https://blog.talosintelligence.com/new-zardoor-backdoor/"
    DaysOfYara  = "43/100"
    hash        = "a99a9f2853ff0ca5b91767096c7f7e977b43e62dd93bde6d79e3407bc01f661d"

  condition:
    for any rsrc in pe.resources:
    (rsrc.type_string == "C\x00O\x00D\x00E\x00R\x00")  }