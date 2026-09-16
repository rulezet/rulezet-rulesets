rule TTP_XOR_QUAD_CurrentVersionRun_770f {
  strings:
    $key_770f = { 24 60 [2] 00 6e [2] 2b 42 [2] 05 60 [2] 11 7b [2] 1e 61 [2] 00 7c [2] 02 7d [2] 19 7b [2] 05 7c [2] 19 53 }

  condition:
    any of them
}