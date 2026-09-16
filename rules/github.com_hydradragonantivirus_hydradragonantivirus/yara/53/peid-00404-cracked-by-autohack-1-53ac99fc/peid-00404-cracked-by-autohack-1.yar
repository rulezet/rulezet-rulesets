rule PEiD_00404_Cracked_by_AutoHack__1__ {
  meta:
    description = "[Cracked by AutoHack (1)]"
    ep_only     = "true"

  strings:
    $a = { FA 50 51 57 56 1E 06 2E 80 3E ?? ?? ?? 74 ?? 8E 06 ?? ?? 2B FF FC }

  condition:
    $a
}