rule TTP_XOR_QUAD_CurrentVersionRun_680f {
  strings:
    $key_680f = { 3b 60 [2] 1f 6e [2] 34 42 [2] 1a 60 [2] 0e 7b [2] 01 61 [2] 1f 7c [2] 1d 7d [2] 06 7b [2] 1a 7c [2] 06 53 }

  condition:
    any of them
}