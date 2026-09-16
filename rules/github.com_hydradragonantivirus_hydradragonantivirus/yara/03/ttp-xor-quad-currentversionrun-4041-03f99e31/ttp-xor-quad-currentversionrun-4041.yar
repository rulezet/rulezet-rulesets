rule TTP_XOR_QUAD_CurrentVersionRun_4041 {
  strings:
    $key_4041 = { 13 2e [2] 37 20 [2] 1c 0c [2] 32 2e [2] 26 35 [2] 29 2f [2] 37 32 [2] 35 33 [2] 2e 35 [2] 32 32 [2] 2e 1d }

  condition:
    any of them
}