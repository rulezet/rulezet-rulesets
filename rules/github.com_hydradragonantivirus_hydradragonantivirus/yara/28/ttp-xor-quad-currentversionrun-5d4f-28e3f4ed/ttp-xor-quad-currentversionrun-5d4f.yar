rule TTP_XOR_QUAD_CurrentVersionRun_5d4f {
  strings:
    $key_5d4f = { 0e 20 [2] 2a 2e [2] 01 02 [2] 2f 20 [2] 3b 3b [2] 34 21 [2] 2a 3c [2] 28 3d [2] 33 3b [2] 2f 3c [2] 33 13 }

  condition:
    any of them
}