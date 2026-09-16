rule TTP_XOR_QUAD_CurrentVersionRun_7f0f {
  strings:
    $key_7f0f = { 2c 60 [2] 08 6e [2] 23 42 [2] 0d 60 [2] 19 7b [2] 16 61 [2] 08 7c [2] 0a 7d [2] 11 7b [2] 0d 7c [2] 11 53 }

  condition:
    any of them
}