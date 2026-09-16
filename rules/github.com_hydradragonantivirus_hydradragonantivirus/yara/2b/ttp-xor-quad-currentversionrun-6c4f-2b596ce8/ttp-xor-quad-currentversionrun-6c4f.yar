rule TTP_XOR_QUAD_CurrentVersionRun_6c4f {
  strings:
    $key_6c4f = { 3f 20 [2] 1b 2e [2] 30 02 [2] 1e 20 [2] 0a 3b [2] 05 21 [2] 1b 3c [2] 19 3d [2] 02 3b [2] 1e 3c [2] 02 13 }

  condition:
    any of them
}