rule TTP_XOR_QUAD_CurrentVersionRun_207e {
  strings:
    $key_207e = { 73 11 [2] 57 1f [2] 7c 33 [2] 52 11 [2] 46 0a [2] 49 10 [2] 57 0d [2] 55 0c [2] 4e 0a [2] 52 0d [2] 4e 22 }

  condition:
    any of them
}