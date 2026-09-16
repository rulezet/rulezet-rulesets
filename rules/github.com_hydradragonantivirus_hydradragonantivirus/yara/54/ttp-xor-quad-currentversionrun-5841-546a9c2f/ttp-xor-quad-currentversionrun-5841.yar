rule TTP_XOR_QUAD_CurrentVersionRun_5841 {
  strings:
    $key_5841 = { 0b 2e [2] 2f 20 [2] 04 0c [2] 2a 2e [2] 3e 35 [2] 31 2f [2] 2f 32 [2] 2d 33 [2] 36 35 [2] 2a 32 [2] 36 1d }

  condition:
    any of them
}