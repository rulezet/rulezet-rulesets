rule TTP_XOR_QUAD_CurrentVersionRun_2058 {
  strings:
    $key_2058 = { 73 37 [2] 57 39 [2] 7c 15 [2] 52 37 [2] 46 2c [2] 49 36 [2] 57 2b [2] 55 2a [2] 4e 2c [2] 52 2b [2] 4e 04 }

  condition:
    any of them
}