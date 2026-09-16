rule TTP_XOR_QUAD_CurrentVersionRun_0b0f {
  strings:
    $key_0b0f = { 58 60 [2] 7c 6e [2] 57 42 [2] 79 60 [2] 6d 7b [2] 62 61 [2] 7c 7c [2] 7e 7d [2] 65 7b [2] 79 7c [2] 65 53 }

  condition:
    any of them
}