rule TTP_XOR_QUAD_CurrentVersionRun_1c3e {
  strings:
    $key_1c3e = { 4f 51 [2] 6b 5f [2] 40 73 [2] 6e 51 [2] 7a 4a [2] 75 50 [2] 6b 4d [2] 69 4c [2] 72 4a [2] 6e 4d [2] 72 62 }

  condition:
    any of them
}