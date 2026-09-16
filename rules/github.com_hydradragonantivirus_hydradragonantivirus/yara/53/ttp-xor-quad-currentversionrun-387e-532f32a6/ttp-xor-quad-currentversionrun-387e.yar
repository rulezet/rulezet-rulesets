rule TTP_XOR_QUAD_CurrentVersionRun_387e {
  strings:
    $key_387e = { 6b 11 [2] 4f 1f [2] 64 33 [2] 4a 11 [2] 5e 0a [2] 51 10 [2] 4f 0d [2] 4d 0c [2] 56 0a [2] 4a 0d [2] 56 22 }

  condition:
    any of them
}