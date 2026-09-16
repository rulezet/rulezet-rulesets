rule TTP_XOR_QUAD_CurrentVersionRun_6c32 {
  strings:
    $key_6c32 = { 3f 5d [2] 1b 53 [2] 30 7f [2] 1e 5d [2] 0a 46 [2] 05 5c [2] 1b 41 [2] 19 40 [2] 02 46 [2] 1e 41 [2] 02 6e }

  condition:
    any of them
}