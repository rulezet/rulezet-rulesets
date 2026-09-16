rule TTP_XOR_QUAD_CurrentVersionRun_403f {
  strings:
    $key_403f = { 13 50 [2] 37 5e [2] 1c 72 [2] 32 50 [2] 26 4b [2] 29 51 [2] 37 4c [2] 35 4d [2] 2e 4b [2] 32 4c [2] 2e 63 }

  condition:
    any of them
}