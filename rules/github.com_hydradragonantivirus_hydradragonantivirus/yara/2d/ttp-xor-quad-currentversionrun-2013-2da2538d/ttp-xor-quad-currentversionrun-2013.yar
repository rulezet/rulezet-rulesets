rule TTP_XOR_QUAD_CurrentVersionRun_2013 {
  strings:
    $key_2013 = { 73 7c [2] 57 72 [2] 7c 5e [2] 52 7c [2] 46 67 [2] 49 7d [2] 57 60 [2] 55 61 [2] 4e 67 [2] 52 60 [2] 4e 4f }

  condition:
    any of them
}