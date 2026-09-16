rule TTP_XOR_QUAD_CurrentVersionRun_3827 {
  strings:
    $key_3827 = { 6b 48 [2] 4f 46 [2] 64 6a [2] 4a 48 [2] 5e 53 [2] 51 49 [2] 4f 54 [2] 4d 55 [2] 56 53 [2] 4a 54 [2] 56 7b }

  condition:
    any of them
}