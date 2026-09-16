rule TTP_XOR_QUAD_CurrentVersionRun_ee17 {
  strings:
    $key_ee17 = { bd 78 [2] 99 76 [2] b2 5a [2] 9c 78 [2] 88 63 [2] 87 79 [2] 99 64 [2] 9b 65 [2] 80 63 [2] 9c 64 [2] 80 4b }

  condition:
    any of them
}