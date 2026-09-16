rule TTP_XOR_QUAD_CurrentVersionRun_5929 {
  strings:
    $key_5929 = { 0a 46 [2] 2e 48 [2] 05 64 [2] 2b 46 [2] 3f 5d [2] 30 47 [2] 2e 5a [2] 2c 5b [2] 37 5d [2] 2b 5a [2] 37 75 }

  condition:
    any of them
}