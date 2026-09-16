rule TTP_XOR_QUAD_CurrentVersionRun_5a0f {
  strings:
    $key_5a0f = { 09 60 [2] 2d 6e [2] 06 42 [2] 28 60 [2] 3c 7b [2] 33 61 [2] 2d 7c [2] 2f 7d [2] 34 7b [2] 28 7c [2] 34 53 }

  condition:
    any of them
}