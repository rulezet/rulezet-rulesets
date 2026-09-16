rule TTP_XOR_QUAD_CurrentVersionRun_e901 {
  strings:
    $key_e901 = { ba 6e [2] 9e 60 [2] b5 4c [2] 9b 6e [2] 8f 75 [2] 80 6f [2] 9e 72 [2] 9c 73 [2] 87 75 [2] 9b 72 [2] 87 5d }

  condition:
    any of them
}