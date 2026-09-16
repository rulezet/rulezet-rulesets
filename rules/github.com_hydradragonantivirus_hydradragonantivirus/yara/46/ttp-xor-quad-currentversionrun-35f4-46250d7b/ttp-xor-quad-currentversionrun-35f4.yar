rule TTP_XOR_QUAD_CurrentVersionRun_35f4 {
  strings:
    $key_35f4 = { 66 9b [2] 42 95 [2] 69 b9 [2] 47 9b [2] 53 80 [2] 5c 9a [2] 42 87 [2] 40 86 [2] 5b 80 [2] 47 87 [2] 5b a8 }

  condition:
    any of them
}