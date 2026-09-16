rule TTP_XOR_QUAD_CurrentVersionRun_577f {
  strings:
    $key_577f = { 04 10 [2] 20 1e [2] 0b 32 [2] 25 10 [2] 31 0b [2] 3e 11 [2] 20 0c [2] 22 0d [2] 39 0b [2] 25 0c [2] 39 23 }

  condition:
    any of them
}