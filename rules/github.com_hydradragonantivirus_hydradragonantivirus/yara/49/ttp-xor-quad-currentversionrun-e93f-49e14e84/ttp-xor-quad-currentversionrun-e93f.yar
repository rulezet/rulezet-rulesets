rule TTP_XOR_QUAD_CurrentVersionRun_e93f {
  strings:
    $key_e93f = { ba 50 [2] 9e 5e [2] b5 72 [2] 9b 50 [2] 8f 4b [2] 80 51 [2] 9e 4c [2] 9c 4d [2] 87 4b [2] 9b 4c [2] 87 63 }

  condition:
    any of them
}