rule TTP_XOR_QUAD_CurrentVersionRun_206d {
  strings:
    $key_206d = { 73 02 [2] 57 0c [2] 7c 20 [2] 52 02 [2] 46 19 [2] 49 03 [2] 57 1e [2] 55 1f [2] 4e 19 [2] 52 1e [2] 4e 31 }

  condition:
    any of them
}