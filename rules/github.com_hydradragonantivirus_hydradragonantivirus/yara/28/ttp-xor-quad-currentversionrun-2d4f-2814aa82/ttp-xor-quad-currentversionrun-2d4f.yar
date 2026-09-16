rule TTP_XOR_QUAD_CurrentVersionRun_2d4f {
  strings:
    $key_2d4f = { 7e 20 [2] 5a 2e [2] 71 02 [2] 5f 20 [2] 4b 3b [2] 44 21 [2] 5a 3c [2] 58 3d [2] 43 3b [2] 5f 3c [2] 43 13 }

  condition:
    any of them
}