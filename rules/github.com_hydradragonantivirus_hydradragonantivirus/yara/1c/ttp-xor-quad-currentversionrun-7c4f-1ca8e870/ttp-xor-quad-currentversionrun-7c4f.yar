rule TTP_XOR_QUAD_CurrentVersionRun_7c4f {
  strings:
    $key_7c4f = { 2f 20 [2] 0b 2e [2] 20 02 [2] 0e 20 [2] 1a 3b [2] 15 21 [2] 0b 3c [2] 09 3d [2] 12 3b [2] 0e 3c [2] 12 13 }

  condition:
    any of them
}