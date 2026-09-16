rule TTP_XOR_QUAD_CurrentVersionRun_05e9 {
  strings:
    $key_05e9 = { 56 86 [2] 72 88 [2] 59 a4 [2] 77 86 [2] 63 9d [2] 6c 87 [2] 72 9a [2] 70 9b [2] 6b 9d [2] 77 9a [2] 6b b5 }

  condition:
    any of them
}