rule TTP_XOR_QUAD_CurrentVersionRun_fde8 {
  strings:
    $key_fde8 = { ae 87 [2] 8a 89 [2] a1 a5 [2] 8f 87 [2] 9b 9c [2] 94 86 [2] 8a 9b [2] 88 9a [2] 93 9c [2] 8f 9b [2] 93 b4 }

  condition:
    any of them
}