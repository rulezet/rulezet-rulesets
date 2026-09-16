rule TTP_XOR_QUAD_CurrentVersionRun_e968 {
  strings:
    $key_e968 = { ba 07 [2] 9e 09 [2] b5 25 [2] 9b 07 [2] 8f 1c [2] 80 06 [2] 9e 1b [2] 9c 1a [2] 87 1c [2] 9b 1b [2] 87 34 }

  condition:
    any of them
}