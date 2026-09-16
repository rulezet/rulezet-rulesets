rule TTP_XOR_QUAD_CurrentVersionRun_5229 {
  strings:
    $key_5229 = { 01 46 [2] 25 48 [2] 0e 64 [2] 20 46 [2] 34 5d [2] 3b 47 [2] 25 5a [2] 27 5b [2] 3c 5d [2] 20 5a [2] 3c 75 }

  condition:
    any of them
}