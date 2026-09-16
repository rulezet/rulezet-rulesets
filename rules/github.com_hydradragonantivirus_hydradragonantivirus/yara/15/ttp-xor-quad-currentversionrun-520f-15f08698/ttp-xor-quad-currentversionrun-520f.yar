rule TTP_XOR_QUAD_CurrentVersionRun_520f {
  strings:
    $key_520f = { 01 60 [2] 25 6e [2] 0e 42 [2] 20 60 [2] 34 7b [2] 3b 61 [2] 25 7c [2] 27 7d [2] 3c 7b [2] 20 7c [2] 3c 53 }

  condition:
    any of them
}