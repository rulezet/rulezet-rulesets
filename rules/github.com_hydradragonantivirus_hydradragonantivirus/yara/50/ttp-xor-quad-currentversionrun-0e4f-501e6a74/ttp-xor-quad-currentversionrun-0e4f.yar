rule TTP_XOR_QUAD_CurrentVersionRun_0e4f {
  strings:
    $key_0e4f = { 5d 20 [2] 79 2e [2] 52 02 [2] 7c 20 [2] 68 3b [2] 67 21 [2] 79 3c [2] 7b 3d [2] 60 3b [2] 7c 3c [2] 60 13 }

  condition:
    any of them
}