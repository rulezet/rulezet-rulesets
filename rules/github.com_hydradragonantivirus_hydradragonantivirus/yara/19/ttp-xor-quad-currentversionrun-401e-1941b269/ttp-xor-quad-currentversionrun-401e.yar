rule TTP_XOR_QUAD_CurrentVersionRun_401e {
  strings:
    $key_401e = { 13 71 [2] 37 7f [2] 1c 53 [2] 32 71 [2] 26 6a [2] 29 70 [2] 37 6d [2] 35 6c [2] 2e 6a [2] 32 6d [2] 2e 42 }

  condition:
    any of them
}