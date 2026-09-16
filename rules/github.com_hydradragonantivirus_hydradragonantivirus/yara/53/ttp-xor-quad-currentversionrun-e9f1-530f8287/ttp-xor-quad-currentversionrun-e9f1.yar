rule TTP_XOR_QUAD_CurrentVersionRun_e9f1 {
  strings:
    $key_e9f1 = { ba 9e [2] 9e 90 [2] b5 bc [2] 9b 9e [2] 8f 85 [2] 80 9f [2] 9e 82 [2] 9c 83 [2] 87 85 [2] 9b 82 [2] 87 ad }

  condition:
    any of them
}