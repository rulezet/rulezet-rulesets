rule TTP_XOR_QUAD_CurrentVersionRun_3e3e {
  strings:
    $key_3e3e = { 6d 51 [2] 49 5f [2] 62 73 [2] 4c 51 [2] 58 4a [2] 57 50 [2] 49 4d [2] 4b 4c [2] 50 4a [2] 4c 4d [2] 50 62 }

  condition:
    any of them
}