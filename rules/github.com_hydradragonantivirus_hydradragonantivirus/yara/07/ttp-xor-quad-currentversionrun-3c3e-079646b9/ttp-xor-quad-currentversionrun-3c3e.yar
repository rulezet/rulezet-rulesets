rule TTP_XOR_QUAD_CurrentVersionRun_3c3e {
  strings:
    $key_3c3e = { 6f 51 [2] 4b 5f [2] 60 73 [2] 4e 51 [2] 5a 4a [2] 55 50 [2] 4b 4d [2] 49 4c [2] 52 4a [2] 4e 4d [2] 52 62 }

  condition:
    any of them
}