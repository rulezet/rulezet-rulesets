rule TTP_XOR_QUAD_CurrentVersionRun_114f {
  strings:
    $key_114f = { 42 20 [2] 66 2e [2] 4d 02 [2] 63 20 [2] 77 3b [2] 78 21 [2] 66 3c [2] 64 3d [2] 7f 3b [2] 63 3c [2] 7f 13 }

  condition:
    any of them
}