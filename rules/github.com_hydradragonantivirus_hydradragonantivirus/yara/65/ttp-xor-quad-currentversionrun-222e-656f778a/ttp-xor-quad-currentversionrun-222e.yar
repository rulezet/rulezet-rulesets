rule TTP_XOR_QUAD_CurrentVersionRun_222e {
  strings:
    $key_222e = { 71 41 [2] 55 4f [2] 7e 63 [2] 50 41 [2] 44 5a [2] 4b 40 [2] 55 5d [2] 57 5c [2] 4c 5a [2] 50 5d [2] 4c 72 }

  condition:
    any of them
}