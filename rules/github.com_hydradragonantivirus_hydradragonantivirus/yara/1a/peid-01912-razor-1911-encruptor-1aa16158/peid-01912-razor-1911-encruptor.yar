rule PEiD_01912_RAZOR_1911_encruptor_ {
  meta:
    description = "[RAZOR 1911 encruptor]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC }

  condition:
    $a
}