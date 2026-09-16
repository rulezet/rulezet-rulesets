rule TTP_XOR_QUAD_CurrentVersionRun_523e {
  strings:
    $key_523e = { 01 51 [2] 25 5f [2] 0e 73 [2] 20 51 [2] 34 4a [2] 3b 50 [2] 25 4d [2] 27 4c [2] 3c 4a [2] 20 4d [2] 3c 62 }

  condition:
    any of them
}