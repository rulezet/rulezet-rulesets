rule TTP_XOR_QUAD_CurrentVersionRun_453c {
  strings:
    $key_453c = { 16 53 [2] 32 5d [2] 19 71 [2] 37 53 [2] 23 48 [2] 2c 52 [2] 32 4f [2] 30 4e [2] 2b 48 [2] 37 4f [2] 2b 60 }

  condition:
    any of them
}