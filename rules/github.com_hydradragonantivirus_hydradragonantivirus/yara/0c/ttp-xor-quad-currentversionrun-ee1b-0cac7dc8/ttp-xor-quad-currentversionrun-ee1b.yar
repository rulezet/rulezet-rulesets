rule TTP_XOR_QUAD_CurrentVersionRun_ee1b {
  strings:
    $key_ee1b = { bd 74 [2] 99 7a [2] b2 56 [2] 9c 74 [2] 88 6f [2] 87 75 [2] 99 68 [2] 9b 69 [2] 80 6f [2] 9c 68 [2] 80 47 }

  condition:
    any of them
}