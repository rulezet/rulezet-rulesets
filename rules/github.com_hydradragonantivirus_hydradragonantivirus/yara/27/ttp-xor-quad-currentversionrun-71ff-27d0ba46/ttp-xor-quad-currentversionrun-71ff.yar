rule TTP_XOR_QUAD_CurrentVersionRun_71ff {
  strings:
    $key_71ff = { 22 90 [2] 06 9e [2] 2d b2 [2] 03 90 [2] 17 8b [2] 18 91 [2] 06 8c [2] 04 8d [2] 1f 8b [2] 03 8c [2] 1f a3 }

  condition:
    any of them
}