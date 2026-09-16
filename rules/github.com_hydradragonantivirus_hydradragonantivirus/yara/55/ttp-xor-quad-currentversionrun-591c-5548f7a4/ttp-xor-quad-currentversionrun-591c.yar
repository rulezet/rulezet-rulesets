rule TTP_XOR_QUAD_CurrentVersionRun_591c {
  strings:
    $key_591c = { 0a 73 [2] 2e 7d [2] 05 51 [2] 2b 73 [2] 3f 68 [2] 30 72 [2] 2e 6f [2] 2c 6e [2] 37 68 [2] 2b 6f [2] 37 40 }

  condition:
    any of them
}