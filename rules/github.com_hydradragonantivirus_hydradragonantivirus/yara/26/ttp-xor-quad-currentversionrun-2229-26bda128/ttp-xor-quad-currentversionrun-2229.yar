rule TTP_XOR_QUAD_CurrentVersionRun_2229 {
  strings:
    $key_2229 = { 71 46 [2] 55 48 [2] 7e 64 [2] 50 46 [2] 44 5d [2] 4b 47 [2] 55 5a [2] 57 5b [2] 4c 5d [2] 50 5a [2] 4c 75 }

  condition:
    any of them
}