rule TTP_XOR_QUAD_CurrentVersionRun_1d4f {
  strings:
    $key_1d4f = { 4e 20 [2] 6a 2e [2] 41 02 [2] 6f 20 [2] 7b 3b [2] 74 21 [2] 6a 3c [2] 68 3d [2] 73 3b [2] 6f 3c [2] 73 13 }

  condition:
    any of them
}