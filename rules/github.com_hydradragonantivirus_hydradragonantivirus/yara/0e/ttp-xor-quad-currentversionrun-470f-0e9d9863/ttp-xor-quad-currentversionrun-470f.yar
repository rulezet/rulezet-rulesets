rule TTP_XOR_QUAD_CurrentVersionRun_470f {
  strings:
    $key_470f = { 14 60 [2] 30 6e [2] 1b 42 [2] 35 60 [2] 21 7b [2] 2e 61 [2] 30 7c [2] 32 7d [2] 29 7b [2] 35 7c [2] 29 53 }

  condition:
    any of them
}