rule TTP_XOR_QUAD_CurrentVersionRun_e93e {
  strings:
    $key_e93e = { ba 51 [2] 9e 5f [2] b5 73 [2] 9b 51 [2] 8f 4a [2] 80 50 [2] 9e 4d [2] 9c 4c [2] 87 4a [2] 9b 4d [2] 87 62 }

  condition:
    any of them
}