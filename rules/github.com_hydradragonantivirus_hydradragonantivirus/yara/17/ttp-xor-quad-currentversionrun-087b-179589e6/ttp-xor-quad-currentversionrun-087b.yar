rule TTP_XOR_QUAD_CurrentVersionRun_087b {
  strings:
    $key_087b = { 5b 14 [2] 7f 1a [2] 54 36 [2] 7a 14 [2] 6e 0f [2] 61 15 [2] 7f 08 [2] 7d 09 [2] 66 0f [2] 7a 08 [2] 66 27 }

  condition:
    any of them
}