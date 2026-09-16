rule TTP_XOR_QUAD_CurrentVersionRun_1c29 {
  strings:
    $key_1c29 = { 4f 46 [2] 6b 48 [2] 40 64 [2] 6e 46 [2] 7a 5d [2] 75 47 [2] 6b 5a [2] 69 5b [2] 72 5d [2] 6e 5a [2] 72 75 }

  condition:
    any of them
}