rule TTP_XOR_QUAD_CurrentVersionRun_3ce8 {
  strings:
    $key_3ce8 = { 6f 87 [2] 4b 89 [2] 60 a5 [2] 4e 87 [2] 5a 9c [2] 55 86 [2] 4b 9b [2] 49 9a [2] 52 9c [2] 4e 9b [2] 52 b4 }

  condition:
    any of them
}