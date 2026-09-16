rule TTP_XOR_QUAD_CurrentVersionRun_6de9 {
  strings:
    $key_6de9 = { 3e 86 [2] 1a 88 [2] 31 a4 [2] 1f 86 [2] 0b 9d [2] 04 87 [2] 1a 9a [2] 18 9b [2] 03 9d [2] 1f 9a [2] 03 b5 }

  condition:
    any of them
}