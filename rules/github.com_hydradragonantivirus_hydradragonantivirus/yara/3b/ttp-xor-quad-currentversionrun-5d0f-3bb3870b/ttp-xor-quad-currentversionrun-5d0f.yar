rule TTP_XOR_QUAD_CurrentVersionRun_5d0f {
  strings:
    $key_5d0f = { 0e 60 [2] 2a 6e [2] 01 42 [2] 2f 60 [2] 3b 7b [2] 34 61 [2] 2a 7c [2] 28 7d [2] 33 7b [2] 2f 7c [2] 33 53 }

  condition:
    any of them
}