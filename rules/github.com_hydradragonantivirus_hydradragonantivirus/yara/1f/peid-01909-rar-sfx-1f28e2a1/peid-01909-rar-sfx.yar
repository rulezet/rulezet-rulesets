rule PEiD_01909_RAR_SFX_ {
  meta:
    description = "[RAR SFX]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 00 00 00 00 90 }

  condition:
    $a
}