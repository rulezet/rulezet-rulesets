rule TTP_XOR_QUAD_CurrentVersionRun_453f {
  strings:
    $key_453f = { 16 50 [2] 32 5e [2] 19 72 [2] 37 50 [2] 23 4b [2] 2c 51 [2] 32 4c [2] 30 4d [2] 2b 4b [2] 37 4c [2] 2b 63 }

  condition:
    any of them
}