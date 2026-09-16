rule TTP_XOR_QUAD_CurrentVersionRun_355f {
  strings:
    $key_355f = { 66 30 [2] 42 3e [2] 69 12 [2] 47 30 [2] 53 2b [2] 5c 31 [2] 42 2c [2] 40 2d [2] 5b 2b [2] 47 2c [2] 5b 03 }

  condition:
    any of them
}