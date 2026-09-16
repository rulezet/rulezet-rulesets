rule TTP_XOR_QUAD_CurrentVersionRun_1a4f {
  strings:
    $key_1a4f = { 49 20 [2] 6d 2e [2] 46 02 [2] 68 20 [2] 7c 3b [2] 73 21 [2] 6d 3c [2] 6f 3d [2] 74 3b [2] 68 3c [2] 74 13 }

  condition:
    any of them
}