rule TTP_XOR_QUAD_CurrentVersionRun_4012 {
  strings:
    $key_4012 = { 13 7d [2] 37 73 [2] 1c 5f [2] 32 7d [2] 26 66 [2] 29 7c [2] 37 61 [2] 35 60 [2] 2e 66 [2] 32 61 [2] 2e 4e }

  condition:
    any of them
}