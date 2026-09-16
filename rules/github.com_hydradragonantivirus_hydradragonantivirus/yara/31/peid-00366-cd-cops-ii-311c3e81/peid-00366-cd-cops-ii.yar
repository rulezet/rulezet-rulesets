rule PEiD_00366_CD_Cops_II_ {
  meta:
    description = "[CD-Cops II]"
    ep_only     = "true"

  strings:
    $a = { 53 60 BD ?? ?? ?? ?? 8D 45 ?? 8D 5D ?? E8 ?? ?? ?? ?? 8D }

  condition:
    $a
}