rule TTP_XOR_QUAD_CurrentVersionRun_273e {
  strings:
    $key_273e = { 74 51 [2] 50 5f [2] 7b 73 [2] 55 51 [2] 41 4a [2] 4e 50 [2] 50 4d [2] 52 4c [2] 49 4a [2] 55 4d [2] 49 62 }

  condition:
    any of them
}