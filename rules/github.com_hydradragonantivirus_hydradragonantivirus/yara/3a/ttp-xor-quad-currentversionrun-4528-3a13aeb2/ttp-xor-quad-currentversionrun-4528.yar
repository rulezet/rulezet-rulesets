rule TTP_XOR_QUAD_CurrentVersionRun_4528 {
  strings:
    $key_4528 = { 16 47 [2] 32 49 [2] 19 65 [2] 37 47 [2] 23 5c [2] 2c 46 [2] 32 5b [2] 30 5a [2] 2b 5c [2] 37 5b [2] 2b 74 }

  condition:
    any of them
}