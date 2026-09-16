rule TTP_XOR_QUAD_CurrentVersionRun_085f {
  strings:
    $key_085f = { 5b 30 [2] 7f 3e [2] 54 12 [2] 7a 30 [2] 6e 2b [2] 61 31 [2] 7f 2c [2] 7d 2d [2] 66 2b [2] 7a 2c [2] 66 03 }

  condition:
    any of them
}