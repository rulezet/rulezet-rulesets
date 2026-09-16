rule TTP_XOR_QUAD_CurrentVersionRun_3627 {
  strings:
    $key_3627 = { 65 48 [2] 41 46 [2] 6a 6a [2] 44 48 [2] 50 53 [2] 5f 49 [2] 41 54 [2] 43 55 [2] 58 53 [2] 44 54 [2] 58 7b }

  condition:
    any of them
}