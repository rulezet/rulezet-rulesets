rule TTP_XOR_QUAD_CurrentVersionRun_0c2e {
  strings:
    $key_0c2e = { 5f 41 [2] 7b 4f [2] 50 63 [2] 7e 41 [2] 6a 5a [2] 65 40 [2] 7b 5d [2] 79 5c [2] 62 5a [2] 7e 5d [2] 62 72 }

  condition:
    any of them
}