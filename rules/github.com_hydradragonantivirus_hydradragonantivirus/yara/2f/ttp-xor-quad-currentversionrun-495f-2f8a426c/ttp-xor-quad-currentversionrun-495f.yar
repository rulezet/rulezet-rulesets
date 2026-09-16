rule TTP_XOR_QUAD_CurrentVersionRun_495f {
  strings:
    $key_495f = { 1a 30 [2] 3e 3e [2] 15 12 [2] 3b 30 [2] 2f 2b [2] 20 31 [2] 3e 2c [2] 3c 2d [2] 27 2b [2] 3b 2c [2] 27 03 }

  condition:
    any of them
}