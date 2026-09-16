rule TTP_XOR_QUAD_CurrentVersionRun_022e {
  strings:
    $key_022e = { 51 41 [2] 75 4f [2] 5e 63 [2] 70 41 [2] 64 5a [2] 6b 40 [2] 75 5d [2] 77 5c [2] 6c 5a [2] 70 5d [2] 6c 72 }

  condition:
    any of them
}