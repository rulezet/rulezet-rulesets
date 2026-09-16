rule TTP_XOR_QUAD_CurrentVersionRun_673e {
  strings:
    $key_673e = { 34 51 [2] 10 5f [2] 3b 73 [2] 15 51 [2] 01 4a [2] 0e 50 [2] 10 4d [2] 12 4c [2] 09 4a [2] 15 4d [2] 09 62 }

  condition:
    any of them
}