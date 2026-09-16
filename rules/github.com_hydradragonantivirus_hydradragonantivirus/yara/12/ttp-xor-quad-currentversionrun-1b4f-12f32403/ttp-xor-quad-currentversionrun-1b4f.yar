rule TTP_XOR_QUAD_CurrentVersionRun_1b4f {
  strings:
    $key_1b4f = { 48 20 [2] 6c 2e [2] 47 02 [2] 69 20 [2] 7d 3b [2] 72 21 [2] 6c 3c [2] 6e 3d [2] 75 3b [2] 69 3c [2] 75 13 }

  condition:
    any of them
}