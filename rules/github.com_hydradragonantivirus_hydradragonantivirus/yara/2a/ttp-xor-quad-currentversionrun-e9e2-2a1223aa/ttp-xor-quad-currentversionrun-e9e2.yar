rule TTP_XOR_QUAD_CurrentVersionRun_e9e2 {
  strings:
    $key_e9e2 = { ba 8d [2] 9e 83 [2] b5 af [2] 9b 8d [2] 8f 96 [2] 80 8c [2] 9e 91 [2] 9c 90 [2] 87 96 [2] 9b 91 [2] 87 be }

  condition:
    any of them
}