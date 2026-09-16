rule TTP_XOR_QUAD_CurrentVersionRun_203e {
  strings:
    $key_203e = { 73 51 [2] 57 5f [2] 7c 73 [2] 52 51 [2] 46 4a [2] 49 50 [2] 57 4d [2] 55 4c [2] 4e 4a [2] 52 4d [2] 4e 62 }

  condition:
    any of them
}