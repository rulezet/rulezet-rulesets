rule TTP_XOR_QUAD_CurrentVersionRun_2115 {
  strings:
    $key_2115 = { 72 7a [2] 56 74 [2] 7d 58 [2] 53 7a [2] 47 61 [2] 48 7b [2] 56 66 [2] 54 67 [2] 4f 61 [2] 53 66 [2] 4f 49 }

  condition:
    any of them
}