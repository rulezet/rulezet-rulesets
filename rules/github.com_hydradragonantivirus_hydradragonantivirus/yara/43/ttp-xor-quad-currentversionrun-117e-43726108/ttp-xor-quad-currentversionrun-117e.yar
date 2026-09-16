rule TTP_XOR_QUAD_CurrentVersionRun_117e {
  strings:
    $key_117e = { 42 11 [2] 66 1f [2] 4d 33 [2] 63 11 [2] 77 0a [2] 78 10 [2] 66 0d [2] 64 0c [2] 7f 0a [2] 63 0d [2] 7f 22 }

  condition:
    any of them
}