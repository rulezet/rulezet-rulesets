rule TTP_XOR_QUAD_CurrentVersionRun_3e2e {
  strings:
    $key_3e2e = { 6d 41 [2] 49 4f [2] 62 63 [2] 4c 41 [2] 58 5a [2] 57 40 [2] 49 5d [2] 4b 5c [2] 50 5a [2] 4c 5d [2] 50 72 }

  condition:
    any of them
}