rule TTP_XOR_QUAD_CurrentVersionRun_e9e0 {
  strings:
    $key_e9e0 = { ba 8f [2] 9e 81 [2] b5 ad [2] 9b 8f [2] 8f 94 [2] 80 8e [2] 9e 93 [2] 9c 92 [2] 87 94 [2] 9b 93 [2] 87 bc }

  condition:
    any of them
}