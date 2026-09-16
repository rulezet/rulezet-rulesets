rule TTP_XOR_QUAD_CurrentVersionRun_2008 {
  strings:
    $key_2008 = { 73 67 [2] 57 69 [2] 7c 45 [2] 52 67 [2] 46 7c [2] 49 66 [2] 57 7b [2] 55 7a [2] 4e 7c [2] 52 7b [2] 4e 54 }

  condition:
    any of them
}