rule TTP_XOR_QUAD_CurrentVersionRun_167e {
  strings:
    $key_167e = { 45 11 [2] 61 1f [2] 4a 33 [2] 64 11 [2] 70 0a [2] 7f 10 [2] 61 0d [2] 63 0c [2] 78 0a [2] 64 0d [2] 78 22 }

  condition:
    any of them
}