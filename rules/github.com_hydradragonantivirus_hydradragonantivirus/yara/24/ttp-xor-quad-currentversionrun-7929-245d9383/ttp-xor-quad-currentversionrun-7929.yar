rule TTP_XOR_QUAD_CurrentVersionRun_7929 {
  strings:
    $key_7929 = { 2a 46 [2] 0e 48 [2] 25 64 [2] 0b 46 [2] 1f 5d [2] 10 47 [2] 0e 5a [2] 0c 5b [2] 17 5d [2] 0b 5a [2] 17 75 }

  condition:
    any of them
}