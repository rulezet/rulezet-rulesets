rule TTP_XOR_QUAD_CurrentVersionRun_5eff {
  strings:
    $key_5eff = { 0d 90 [2] 29 9e [2] 02 b2 [2] 2c 90 [2] 38 8b [2] 37 91 [2] 29 8c [2] 2b 8d [2] 30 8b [2] 2c 8c [2] 30 a3 }

  condition:
    any of them
}