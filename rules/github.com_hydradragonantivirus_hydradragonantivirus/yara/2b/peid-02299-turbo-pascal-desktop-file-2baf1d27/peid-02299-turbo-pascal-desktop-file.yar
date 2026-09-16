rule PEiD_02299_Turbo_Pascal_Desktop_File_ {
  meta:
    description = "[Turbo Pascal Desktop File]"
    ep_only     = "false"

  strings:
    $a = "Turbo Pascal Desktop"

  condition:
    $a
}