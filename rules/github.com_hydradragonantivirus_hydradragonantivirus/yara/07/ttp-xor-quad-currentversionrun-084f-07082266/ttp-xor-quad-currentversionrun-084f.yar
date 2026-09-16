rule TTP_XOR_QUAD_CurrentVersionRun_084f {
  strings:
    $key_084f = { 5b 20 [2] 7f 2e [2] 54 02 [2] 7a 20 [2] 6e 3b [2] 61 21 [2] 7f 3c [2] 7d 3d [2] 66 3b [2] 7a 3c [2] 66 13 }

  condition:
    any of them
}