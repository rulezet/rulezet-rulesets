rule TTP_XOR_QUAD_CurrentVersionRun_e90c {
  strings:
    $key_e90c = { ba 63 [2] 9e 6d [2] b5 41 [2] 9b 63 [2] 8f 78 [2] 80 62 [2] 9e 7f [2] 9c 7e [2] 87 78 [2] 9b 7f [2] 87 50 }

  condition:
    any of them
}