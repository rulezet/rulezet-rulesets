rule TTP_XOR_QUAD_CurrentVersionRun_fce9 {
  strings:
    $key_fce9 = { af 86 [2] 8b 88 [2] a0 a4 [2] 8e 86 [2] 9a 9d [2] 95 87 [2] 8b 9a [2] 89 9b [2] 92 9d [2] 8e 9a [2] 92 b5 }

  condition:
    any of them
}