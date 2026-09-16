rule TTP_XOR_QUAD_CurrentVersionRun_14e8 {
  strings:
    $key_14e8 = { 47 87 [2] 63 89 [2] 48 a5 [2] 66 87 [2] 72 9c [2] 7d 86 [2] 63 9b [2] 61 9a [2] 7a 9c [2] 66 9b [2] 7a b4 }

  condition:
    any of them
}