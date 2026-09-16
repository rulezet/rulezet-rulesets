rule TTP_XOR_QUAD_CurrentVersionRun_004f {
  strings:
    $key_004f = { 53 20 [2] 77 2e [2] 5c 02 [2] 72 20 [2] 66 3b [2] 69 21 [2] 77 3c [2] 75 3d [2] 6e 3b [2] 72 3c [2] 6e 13 }

  condition:
    any of them
}