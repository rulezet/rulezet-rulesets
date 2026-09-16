rule TTP_XOR_QUAD_CurrentVersionRun_f13e {
  strings:
    $key_f13e = { a2 51 [2] 86 5f [2] ad 73 [2] 83 51 [2] 97 4a [2] 98 50 [2] 86 4d [2] 84 4c [2] 9f 4a [2] 83 4d [2] 9f 62 }

  condition:
    any of them
}