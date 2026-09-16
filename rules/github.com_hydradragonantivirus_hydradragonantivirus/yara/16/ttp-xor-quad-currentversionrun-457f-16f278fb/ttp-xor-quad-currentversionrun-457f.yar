rule TTP_XOR_QUAD_CurrentVersionRun_457f {
  strings:
    $key_457f = { 16 10 [2] 32 1e [2] 19 32 [2] 37 10 [2] 23 0b [2] 2c 11 [2] 32 0c [2] 30 0d [2] 2b 0b [2] 37 0c [2] 2b 23 }

  condition:
    any of them
}