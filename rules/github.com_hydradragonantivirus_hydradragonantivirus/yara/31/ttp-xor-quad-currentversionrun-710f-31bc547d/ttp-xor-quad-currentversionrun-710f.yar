rule TTP_XOR_QUAD_CurrentVersionRun_710f {
  strings:
    $key_710f = { 22 60 [2] 06 6e [2] 2d 42 [2] 03 60 [2] 17 7b [2] 18 61 [2] 06 7c [2] 04 7d [2] 1f 7b [2] 03 7c [2] 1f 53 }

  condition:
    any of them
}