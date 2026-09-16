rule TTP_XOR_QUAD_CurrentVersionRun_eeeb {
  strings:
    $key_eeeb = { bd 84 [2] 99 8a [2] b2 a6 [2] 9c 84 [2] 88 9f [2] 87 85 [2] 99 98 [2] 9b 99 [2] 80 9f [2] 9c 98 [2] 80 b7 }

  condition:
    any of them
}