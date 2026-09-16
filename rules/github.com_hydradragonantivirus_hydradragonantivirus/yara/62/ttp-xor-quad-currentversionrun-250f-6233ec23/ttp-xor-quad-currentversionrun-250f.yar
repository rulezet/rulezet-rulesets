rule TTP_XOR_QUAD_CurrentVersionRun_250f {
  strings:
    $key_250f = { 76 60 [2] 52 6e [2] 79 42 [2] 57 60 [2] 43 7b [2] 4c 61 [2] 52 7c [2] 50 7d [2] 4b 7b [2] 57 7c [2] 4b 53 }

  condition:
    any of them
}