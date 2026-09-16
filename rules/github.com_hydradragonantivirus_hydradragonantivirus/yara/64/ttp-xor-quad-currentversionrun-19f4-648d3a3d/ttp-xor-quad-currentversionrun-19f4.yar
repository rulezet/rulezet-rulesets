rule TTP_XOR_QUAD_CurrentVersionRun_19f4 {
  strings:
    $key_19f4 = { 4a 9b [2] 6e 95 [2] 45 b9 [2] 6b 9b [2] 7f 80 [2] 70 9a [2] 6e 87 [2] 6c 86 [2] 77 80 [2] 6b 87 [2] 77 a8 }

  condition:
    any of them
}