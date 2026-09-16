rule TTP_XOR_QUAD_CurrentVersionRun_26e9 {
  strings:
    $key_26e9 = { 75 86 [2] 51 88 [2] 7a a4 [2] 54 86 [2] 40 9d [2] 4f 87 [2] 51 9a [2] 53 9b [2] 48 9d [2] 54 9a [2] 48 b5 }

  condition:
    any of them
}