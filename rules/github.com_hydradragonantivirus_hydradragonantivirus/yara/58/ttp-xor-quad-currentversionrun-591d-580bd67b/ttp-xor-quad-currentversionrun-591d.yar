rule TTP_XOR_QUAD_CurrentVersionRun_591d {
  strings:
    $key_591d = { 0a 72 [2] 2e 7c [2] 05 50 [2] 2b 72 [2] 3f 69 [2] 30 73 [2] 2e 6e [2] 2c 6f [2] 37 69 [2] 2b 6e [2] 37 41 }

  condition:
    any of them
}