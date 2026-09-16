rule TTP_XOR_QUAD_CurrentVersionRun_6b3e {
  strings:
    $key_6b3e = { 38 51 [2] 1c 5f [2] 37 73 [2] 19 51 [2] 0d 4a [2] 02 50 [2] 1c 4d [2] 1e 4c [2] 05 4a [2] 19 4d [2] 05 62 }

  condition:
    any of them
}