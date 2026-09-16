rule TTP_XOR_QUAD_CurrentVersionRun_794f {
  strings:
    $key_794f = { 2a 20 [2] 0e 2e [2] 25 02 [2] 0b 20 [2] 1f 3b [2] 10 21 [2] 0e 3c [2] 0c 3d [2] 17 3b [2] 0b 3c [2] 17 13 }

  condition:
    any of them
}