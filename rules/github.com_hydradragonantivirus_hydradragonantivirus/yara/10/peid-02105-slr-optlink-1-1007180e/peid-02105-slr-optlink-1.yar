rule PEiD_02105_SLR__OPTLINK___1__ {
  meta:
    description = "[SLR (OPTLINK) (1)]"
    ep_only     = "true"

  strings:
    $a = { 87 C0 EB ?? 71 ?? 02 D8 }

  condition:
    $a
}