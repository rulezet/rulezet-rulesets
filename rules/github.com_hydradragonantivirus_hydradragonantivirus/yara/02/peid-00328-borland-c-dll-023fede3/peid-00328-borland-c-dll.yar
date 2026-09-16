rule PEiD_00328_Borland_C___DLL_ {
  meta:
    description = "[Borland C++ DLL]"
    ep_only     = "true"

  strings:
    $a = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3 8B }

  condition:
    $a
}