rule TTP_XOR_QUAD_CurrentVersionRun_600f {
  strings:
    $key_600f = { 33 60 [2] 17 6e [2] 3c 42 [2] 12 60 [2] 06 7b [2] 09 61 [2] 17 7c [2] 15 7d [2] 0e 7b [2] 12 7c [2] 0e 53 }

  condition:
    any of them
}