rule TTP_XOR_QUAD_CurrentVersionRun_5f0f {
  strings:
    $key_5f0f = { 0c 60 [2] 28 6e [2] 03 42 [2] 2d 60 [2] 39 7b [2] 36 61 [2] 28 7c [2] 2a 7d [2] 31 7b [2] 2d 7c [2] 31 53 }

  condition:
    any of them
}