rule TTP_XOR_QUAD_CurrentVersionRun_475f {
  strings:
    $key_475f = { 14 30 [2] 30 3e [2] 1b 12 [2] 35 30 [2] 21 2b [2] 2e 31 [2] 30 2c [2] 32 2d [2] 29 2b [2] 35 2c [2] 29 03 }

  condition:
    any of them
}