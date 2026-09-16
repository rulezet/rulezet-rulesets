rule TTP_XOR_QUAD_CurrentVersionRun_e91b {
  strings:
    $key_e91b = { ba 74 [2] 9e 7a [2] b5 56 [2] 9b 74 [2] 8f 6f [2] 80 75 [2] 9e 68 [2] 9c 69 [2] 87 6f [2] 9b 68 [2] 87 47 }

  condition:
    any of them
}