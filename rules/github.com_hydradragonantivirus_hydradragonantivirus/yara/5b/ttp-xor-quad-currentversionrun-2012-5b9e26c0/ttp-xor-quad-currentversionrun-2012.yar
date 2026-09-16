rule TTP_XOR_QUAD_CurrentVersionRun_2012 {
  strings:
    $key_2012 = { 73 7d [2] 57 73 [2] 7c 5f [2] 52 7d [2] 46 66 [2] 49 7c [2] 57 61 [2] 55 60 [2] 4e 66 [2] 52 61 [2] 4e 4e }

  condition:
    any of them
}