rule TTP_XOR_QUAD_CurrentVersionRun_427f {
  strings:
    $key_427f = { 11 10 [2] 35 1e [2] 1e 32 [2] 30 10 [2] 24 0b [2] 2b 11 [2] 35 0c [2] 37 0d [2] 2c 0b [2] 30 0c [2] 2c 23 }

  condition:
    any of them
}