rule TTP_XOR_QUAD_CurrentVersionRun_400c {
  strings:
    $key_400c = { 13 63 [2] 37 6d [2] 1c 41 [2] 32 63 [2] 26 78 [2] 29 62 [2] 37 7f [2] 35 7e [2] 2e 78 [2] 32 7f [2] 2e 50 }

  condition:
    any of them
}