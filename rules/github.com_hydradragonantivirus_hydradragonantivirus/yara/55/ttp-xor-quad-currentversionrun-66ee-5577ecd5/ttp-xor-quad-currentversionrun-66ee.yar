rule TTP_XOR_QUAD_CurrentVersionRun_66ee {
  strings:
    $key_66ee = { 35 81 [2] 11 8f [2] 3a a3 [2] 14 81 [2] 00 9a [2] 0f 80 [2] 11 9d [2] 13 9c [2] 08 9a [2] 14 9d [2] 08 b2 }

  condition:
    any of them
}