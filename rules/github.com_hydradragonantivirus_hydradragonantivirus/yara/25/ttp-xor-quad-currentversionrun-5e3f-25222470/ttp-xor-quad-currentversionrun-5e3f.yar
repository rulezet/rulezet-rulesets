rule TTP_XOR_QUAD_CurrentVersionRun_5e3f {
  strings:
    $key_5e3f = { 0d 50 [2] 29 5e [2] 02 72 [2] 2c 50 [2] 38 4b [2] 37 51 [2] 29 4c [2] 2b 4d [2] 30 4b [2] 2c 4c [2] 30 63 }

  condition:
    any of them
}