rule TTP_XOR_QUAD_CurrentVersionRun_6d4f {
  strings:
    $key_6d4f = { 3e 20 [2] 1a 2e [2] 31 02 [2] 1f 20 [2] 0b 3b [2] 04 21 [2] 1a 3c [2] 18 3d [2] 03 3b [2] 1f 3c [2] 03 13 }

  condition:
    any of them
}