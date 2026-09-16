rule TTP_XOR_QUAD_CurrentVersionRun_e971 {
  strings:
    $key_e971 = { ba 1e [2] 9e 10 [2] b5 3c [2] 9b 1e [2] 8f 05 [2] 80 1f [2] 9e 02 [2] 9c 03 [2] 87 05 [2] 9b 02 [2] 87 2d }

  condition:
    any of them
}