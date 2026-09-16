rule TTP_XOR_QUAD_CurrentVersionRun_296e {
  strings:
    $key_296e = { 7a 01 [2] 5e 0f [2] 75 23 [2] 5b 01 [2] 4f 1a [2] 40 00 [2] 5e 1d [2] 5c 1c [2] 47 1a [2] 5b 1d [2] 47 32 }

  condition:
    any of them
}