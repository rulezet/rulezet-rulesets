rule TTP_XOR_QUAD_CurrentVersionRun_0e2e {
  strings:
    $key_0e2e = { 5d 41 [2] 79 4f [2] 52 63 [2] 7c 41 [2] 68 5a [2] 67 40 [2] 79 5d [2] 7b 5c [2] 60 5a [2] 7c 5d [2] 60 72 }

  condition:
    any of them
}