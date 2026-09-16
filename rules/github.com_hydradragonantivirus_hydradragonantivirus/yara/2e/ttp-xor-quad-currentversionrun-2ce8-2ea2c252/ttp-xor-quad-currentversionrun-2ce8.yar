rule TTP_XOR_QUAD_CurrentVersionRun_2ce8 {
  strings:
    $key_2ce8 = { 7f 87 [2] 5b 89 [2] 70 a5 [2] 5e 87 [2] 4a 9c [2] 45 86 [2] 5b 9b [2] 59 9a [2] 42 9c [2] 5e 9b [2] 42 b4 }

  condition:
    any of them
}