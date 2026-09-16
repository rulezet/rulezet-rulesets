rule TTP_XOR_QUAD_CurrentVersionRun_591f {
  strings:
    $key_591f = { 0a 70 [2] 2e 7e [2] 05 52 [2] 2b 70 [2] 3f 6b [2] 30 71 [2] 2e 6c [2] 2c 6d [2] 37 6b [2] 2b 6c [2] 37 43 }

  condition:
    any of them
}