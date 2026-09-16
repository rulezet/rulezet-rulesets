rule TTP_XOR_QUAD_CurrentVersionRun_e96b {
  strings:
    $key_e96b = { ba 04 [2] 9e 0a [2] b5 26 [2] 9b 04 [2] 8f 1f [2] 80 05 [2] 9e 18 [2] 9c 19 [2] 87 1f [2] 9b 18 [2] 87 37 }

  condition:
    any of them
}