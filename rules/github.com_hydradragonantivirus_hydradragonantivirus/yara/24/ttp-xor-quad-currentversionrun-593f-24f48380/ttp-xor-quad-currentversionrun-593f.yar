rule TTP_XOR_QUAD_CurrentVersionRun_593f {
  strings:
    $key_593f = { 0a 50 [2] 2e 5e [2] 05 72 [2] 2b 50 [2] 3f 4b [2] 30 51 [2] 2e 4c [2] 2c 4d [2] 37 4b [2] 2b 4c [2] 37 63 }

  condition:
    any of them
}