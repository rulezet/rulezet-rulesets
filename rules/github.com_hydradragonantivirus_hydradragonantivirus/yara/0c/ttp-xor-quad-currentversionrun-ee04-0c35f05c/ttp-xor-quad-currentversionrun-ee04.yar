rule TTP_XOR_QUAD_CurrentVersionRun_ee04 {
  strings:
    $key_ee04 = { bd 6b [2] 99 65 [2] b2 49 [2] 9c 6b [2] 88 70 [2] 87 6a [2] 99 77 [2] 9b 76 [2] 80 70 [2] 9c 77 [2] 80 58 }

  condition:
    any of them
}