rule TTP_XOR_QUAD_CurrentVersionRun_e959 {
  strings:
    $key_e959 = { ba 36 [2] 9e 38 [2] b5 14 [2] 9b 36 [2] 8f 2d [2] 80 37 [2] 9e 2a [2] 9c 2b [2] 87 2d [2] 9b 2a [2] 87 05 }

  condition:
    any of them
}