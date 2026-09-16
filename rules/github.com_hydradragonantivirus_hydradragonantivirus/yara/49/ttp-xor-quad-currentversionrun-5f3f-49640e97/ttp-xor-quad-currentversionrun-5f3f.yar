rule TTP_XOR_QUAD_CurrentVersionRun_5f3f {
  strings:
    $key_5f3f = { 0c 50 [2] 28 5e [2] 03 72 [2] 2d 50 [2] 39 4b [2] 36 51 [2] 28 4c [2] 2a 4d [2] 31 4b [2] 2d 4c [2] 31 63 }

  condition:
    any of them
}