rule TTP_XOR_QUAD_CurrentVersionRun_420f {
  strings:
    $key_420f = { 11 60 [2] 35 6e [2] 1e 42 [2] 30 60 [2] 24 7b [2] 2b 61 [2] 35 7c [2] 37 7d [2] 2c 7b [2] 30 7c [2] 2c 53 }

  condition:
    any of them
}