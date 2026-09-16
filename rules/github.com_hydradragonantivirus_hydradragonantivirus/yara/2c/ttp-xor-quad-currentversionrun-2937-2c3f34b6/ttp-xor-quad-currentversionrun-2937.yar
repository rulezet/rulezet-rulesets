rule TTP_XOR_QUAD_CurrentVersionRun_2937 {
  strings:
    $key_2937 = { 7a 58 [2] 5e 56 [2] 75 7a [2] 5b 58 [2] 4f 43 [2] 40 59 [2] 5e 44 [2] 5c 45 [2] 47 43 [2] 5b 44 [2] 47 6b }

  condition:
    any of them
}