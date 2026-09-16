rule TTP_XOR_QUAD_CurrentVersionRun_7c0f {
  strings:
    $key_7c0f = { 2f 60 [2] 0b 6e [2] 20 42 [2] 0e 60 [2] 1a 7b [2] 15 61 [2] 0b 7c [2] 09 7d [2] 12 7b [2] 0e 7c [2] 12 53 }

  condition:
    any of them
}