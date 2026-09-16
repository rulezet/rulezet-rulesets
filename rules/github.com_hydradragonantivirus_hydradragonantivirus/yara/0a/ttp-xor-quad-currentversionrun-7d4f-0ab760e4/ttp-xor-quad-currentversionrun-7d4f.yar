rule TTP_XOR_QUAD_CurrentVersionRun_7d4f {
  strings:
    $key_7d4f = { 2e 20 [2] 0a 2e [2] 21 02 [2] 0f 20 [2] 1b 3b [2] 14 21 [2] 0a 3c [2] 08 3d [2] 13 3b [2] 0f 3c [2] 13 13 }

  condition:
    any of them
}