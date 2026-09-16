rule TTP_XOR_QUAD_CurrentVersionRun_5f1f {
  strings:
    $key_5f1f = { 0c 70 [2] 28 7e [2] 03 52 [2] 2d 70 [2] 39 6b [2] 36 71 [2] 28 6c [2] 2a 6d [2] 31 6b [2] 2d 6c [2] 31 43 }

  condition:
    any of them
}