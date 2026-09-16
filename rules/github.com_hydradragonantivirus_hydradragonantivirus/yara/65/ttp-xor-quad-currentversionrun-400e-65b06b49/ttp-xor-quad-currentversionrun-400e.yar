rule TTP_XOR_QUAD_CurrentVersionRun_400e {
  strings:
    $key_400e = { 13 61 [2] 37 6f [2] 1c 43 [2] 32 61 [2] 26 7a [2] 29 60 [2] 37 7d [2] 35 7c [2] 2e 7a [2] 32 7d [2] 2e 52 }

  condition:
    any of them
}