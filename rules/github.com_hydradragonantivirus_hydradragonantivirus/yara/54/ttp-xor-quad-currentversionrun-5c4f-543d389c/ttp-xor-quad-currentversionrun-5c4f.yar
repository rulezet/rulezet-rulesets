rule TTP_XOR_QUAD_CurrentVersionRun_5c4f {
  strings:
    $key_5c4f = { 0f 20 [2] 2b 2e [2] 00 02 [2] 2e 20 [2] 3a 3b [2] 35 21 [2] 2b 3c [2] 29 3d [2] 32 3b [2] 2e 3c [2] 32 13 }

  condition:
    any of them
}