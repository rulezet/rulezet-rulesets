rule TTP_XOR_QUAD_CurrentVersionRun_ee7b {
  strings:
    $key_ee7b = { bd 14 [2] 99 1a [2] b2 36 [2] 9c 14 [2] 88 0f [2] 87 15 [2] 99 08 [2] 9b 09 [2] 80 0f [2] 9c 08 [2] 80 27 }

  condition:
    any of them
}