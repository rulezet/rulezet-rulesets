rule TTP_XOR_QUAD_CurrentVersionRun_563e {
  strings:
    $key_563e = { 05 51 [2] 21 5f [2] 0a 73 [2] 24 51 [2] 30 4a [2] 3f 50 [2] 21 4d [2] 23 4c [2] 38 4a [2] 24 4d [2] 38 62 }

  condition:
    any of them
}