rule TTP_XOR_QUAD_CurrentVersionRun_402f {
  strings:
    $key_402f = { 13 40 [2] 37 4e [2] 1c 62 [2] 32 40 [2] 26 5b [2] 29 41 [2] 37 5c [2] 35 5d [2] 2e 5b [2] 32 5c [2] 2e 73 }

  condition:
    any of them
}