rule TTP_XOR_QUAD_CurrentVersionRun_1b0f {
  strings:
    $key_1b0f = { 48 60 [2] 6c 6e [2] 47 42 [2] 69 60 [2] 7d 7b [2] 72 61 [2] 6c 7c [2] 6e 7d [2] 75 7b [2] 69 7c [2] 75 53 }

  condition:
    any of them
}