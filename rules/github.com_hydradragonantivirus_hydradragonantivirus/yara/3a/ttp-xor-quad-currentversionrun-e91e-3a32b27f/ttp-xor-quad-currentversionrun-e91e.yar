rule TTP_XOR_QUAD_CurrentVersionRun_e91e {
  strings:
    $key_e91e = { ba 71 [2] 9e 7f [2] b5 53 [2] 9b 71 [2] 8f 6a [2] 80 70 [2] 9e 6d [2] 9c 6c [2] 87 6a [2] 9b 6d [2] 87 42 }

  condition:
    any of them
}