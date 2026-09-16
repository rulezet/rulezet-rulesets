rule TTP_XOR_QUAD_CurrentVersionRun_597c {
  strings:
    $key_597c = { 0a 13 [2] 2e 1d [2] 05 31 [2] 2b 13 [2] 3f 08 [2] 30 12 [2] 2e 0f [2] 2c 0e [2] 37 08 [2] 2b 0f [2] 37 20 }

  condition:
    any of them
}