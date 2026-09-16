rule TTP_XOR_QUAD_CurrentVersionRun_3de9 {
  strings:
    $key_3de9 = { 6e 86 [2] 4a 88 [2] 61 a4 [2] 4f 86 [2] 5b 9d [2] 54 87 [2] 4a 9a [2] 48 9b [2] 53 9d [2] 4f 9a [2] 53 b5 }

  condition:
    any of them
}