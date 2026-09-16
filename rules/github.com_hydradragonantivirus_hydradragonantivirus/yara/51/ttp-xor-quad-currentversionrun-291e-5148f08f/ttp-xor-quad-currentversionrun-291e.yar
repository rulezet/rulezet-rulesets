rule TTP_XOR_QUAD_CurrentVersionRun_291e {
  strings:
    $key_291e = { 7a 71 [2] 5e 7f [2] 75 53 [2] 5b 71 [2] 4f 6a [2] 40 70 [2] 5e 6d [2] 5c 6c [2] 47 6a [2] 5b 6d [2] 47 42 }

  condition:
    any of them
}