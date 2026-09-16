rule TTP_XOR_QUAD_CurrentVersionRun_3d6f {
  strings:
    $key_3d6f = { 6e 00 [2] 4a 0e [2] 61 22 [2] 4f 00 [2] 5b 1b [2] 54 01 [2] 4a 1c [2] 48 1d [2] 53 1b [2] 4f 1c [2] 53 33 }

  condition:
    any of them
}