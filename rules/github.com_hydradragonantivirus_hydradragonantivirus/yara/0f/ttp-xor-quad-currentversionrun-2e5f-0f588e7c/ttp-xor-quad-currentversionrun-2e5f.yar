rule TTP_XOR_QUAD_CurrentVersionRun_2e5f {
  strings:
    $key_2e5f = { 7d 30 [2] 59 3e [2] 72 12 [2] 5c 30 [2] 48 2b [2] 47 31 [2] 59 2c [2] 5b 2d [2] 40 2b [2] 5c 2c [2] 40 03 }

  condition:
    any of them
}