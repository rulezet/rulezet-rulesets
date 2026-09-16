rule TTP_XOR_QUAD_CurrentVersionRun_e90d {
  strings:
    $key_e90d = { ba 62 [2] 9e 6c [2] b5 40 [2] 9b 62 [2] 8f 79 [2] 80 63 [2] 9e 7e [2] 9c 7f [2] 87 79 [2] 9b 7e [2] 87 51 }

  condition:
    any of them
}