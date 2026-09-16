rule TTP_XOR_QUAD_CurrentVersionRun_e90e {
  strings:
    $key_e90e = { ba 61 [2] 9e 6f [2] b5 43 [2] 9b 61 [2] 8f 7a [2] 80 60 [2] 9e 7d [2] 9c 7c [2] 87 7a [2] 9b 7d [2] 87 52 }

  condition:
    any of them
}