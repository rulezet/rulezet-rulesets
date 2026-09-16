rule TTP_XOR_QUAD_CurrentVersionRun_5922 {
  strings:
    $key_5922 = { 0a 4d [2] 2e 43 [2] 05 6f [2] 2b 4d [2] 3f 56 [2] 30 4c [2] 2e 51 [2] 2c 50 [2] 37 56 [2] 2b 51 [2] 37 7e }

  condition:
    any of them
}