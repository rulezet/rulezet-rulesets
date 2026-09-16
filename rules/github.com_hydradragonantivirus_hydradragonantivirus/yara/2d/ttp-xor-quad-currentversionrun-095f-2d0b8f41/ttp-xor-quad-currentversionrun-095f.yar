rule TTP_XOR_QUAD_CurrentVersionRun_095f {
  strings:
    $key_095f = { 5a 30 [2] 7e 3e [2] 55 12 [2] 7b 30 [2] 6f 2b [2] 60 31 [2] 7e 2c [2] 7c 2d [2] 67 2b [2] 7b 2c [2] 67 03 }

  condition:
    any of them
}