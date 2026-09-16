rule TTP_XOR_QUAD_CurrentVersionRun_504f {
  strings:
    $key_504f = { 03 20 [2] 27 2e [2] 0c 02 [2] 22 20 [2] 36 3b [2] 39 21 [2] 27 3c [2] 25 3d [2] 3e 3b [2] 22 3c [2] 3e 13 }

  condition:
    any of them
}