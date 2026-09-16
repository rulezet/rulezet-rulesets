rule TTP_XOR_QUAD_CurrentVersionRun_ee09 {
  strings:
    $key_ee09 = { bd 66 [2] 99 68 [2] b2 44 [2] 9c 66 [2] 88 7d [2] 87 67 [2] 99 7a [2] 9b 7b [2] 80 7d [2] 9c 7a [2] 80 55 }

  condition:
    any of them
}