rule TTP_XOR_QUAD_CurrentVersionRun_550f {
  strings:
    $key_550f = { 06 60 [2] 22 6e [2] 09 42 [2] 27 60 [2] 33 7b [2] 3c 61 [2] 22 7c [2] 20 7d [2] 3b 7b [2] 27 7c [2] 3b 53 }

  condition:
    any of them
}