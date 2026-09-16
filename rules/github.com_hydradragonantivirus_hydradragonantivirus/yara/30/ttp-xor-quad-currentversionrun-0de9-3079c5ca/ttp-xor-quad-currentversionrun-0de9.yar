rule TTP_XOR_QUAD_CurrentVersionRun_0de9 {
  strings:
    $key_0de9 = { 5e 86 [2] 7a 88 [2] 51 a4 [2] 7f 86 [2] 6b 9d [2] 64 87 [2] 7a 9a [2] 78 9b [2] 63 9d [2] 7f 9a [2] 63 b5 }

  condition:
    any of them
}