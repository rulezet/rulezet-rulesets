rule TTP_XOR_QUAD_CurrentVersionRun_5912 {
  strings:
    $key_5912 = { 0a 7d [2] 2e 73 [2] 05 5f [2] 2b 7d [2] 3f 66 [2] 30 7c [2] 2e 61 [2] 2c 60 [2] 37 66 [2] 2b 61 [2] 37 4e }

  condition:
    any of them
}