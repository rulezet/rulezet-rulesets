rule PEiD_02298_Turbo_Pascal_Configuration_File_ {
  meta:
    description = "[Turbo Pascal Configuration File]"
    ep_only     = "false"

  strings:
    $a = "Turbo Pascal Configuration"

  condition:
    $a
}