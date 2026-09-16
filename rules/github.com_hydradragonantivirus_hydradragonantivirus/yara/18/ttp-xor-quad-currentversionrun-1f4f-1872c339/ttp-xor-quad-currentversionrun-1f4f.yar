rule TTP_XOR_QUAD_CurrentVersionRun_1f4f {
  strings:
    $key_1f4f = { 4c 20 [2] 68 2e [2] 43 02 [2] 6d 20 [2] 79 3b [2] 76 21 [2] 68 3c [2] 6a 3d [2] 71 3b [2] 6d 3c [2] 71 13 }

  condition:
    any of them
}