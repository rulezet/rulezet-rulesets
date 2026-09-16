rule TTP_XOR_QUAD_CurrentVersionRun_1b2e {
  strings:
    $key_1b2e = { 48 41 [2] 6c 4f [2] 47 63 [2] 69 41 [2] 7d 5a [2] 72 40 [2] 6c 5d [2] 6e 5c [2] 75 5a [2] 69 5d [2] 75 72 }

  condition:
    any of them
}