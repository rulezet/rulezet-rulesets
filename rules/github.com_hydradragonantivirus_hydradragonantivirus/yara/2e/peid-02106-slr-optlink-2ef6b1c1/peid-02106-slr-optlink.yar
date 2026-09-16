rule PEiD_02106_SLR__OPTLINK__ {
  meta:
    description = "[SLR (OPTLINK)]"
    ep_only     = "true"

  strings:
    $a = { BF ?? ?? 8E DF FA 8E D7 81 C4 ?? ?? FB B4 30 CD 21 }

  condition:
    $a
}