rule TTP_XOR_QUAD_CurrentVersionRun_5901 {
  strings:
    $key_5901 = { 0a 6e [2] 2e 60 [2] 05 4c [2] 2b 6e [2] 3f 75 [2] 30 6f [2] 2e 72 [2] 2c 73 [2] 37 75 [2] 2b 72 [2] 37 5d }

  condition:
    any of them
}