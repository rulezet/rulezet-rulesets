rule PEiD_02307_TXT2COM_v2_06_ {
  meta:
    description = "[TXT2COM v2.06]"
    ep_only     = "true"

  strings:
    $a = { 8D 26 ?? ?? E8 ?? ?? B8 ?? ?? CD 21 CD 20 54 58 54 32 43 4F 4D 20 }

  condition:
    $a
}