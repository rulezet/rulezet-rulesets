rule TTP_XOR_QUAD_CurrentVersionRun_650f {
  strings:
    $key_650f = { 36 60 [2] 12 6e [2] 39 42 [2] 17 60 [2] 03 7b [2] 0c 61 [2] 12 7c [2] 10 7d [2] 0b 7b [2] 17 7c [2] 0b 53 }

  condition:
    any of them
}