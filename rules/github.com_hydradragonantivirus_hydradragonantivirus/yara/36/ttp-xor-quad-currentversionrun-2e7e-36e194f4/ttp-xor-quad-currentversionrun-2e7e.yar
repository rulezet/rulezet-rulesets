rule TTP_XOR_QUAD_CurrentVersionRun_2e7e {
  strings:
    $key_2e7e = { 7d 11 [2] 59 1f [2] 72 33 [2] 5c 11 [2] 48 0a [2] 47 10 [2] 59 0d [2] 5b 0c [2] 40 0a [2] 5c 0d [2] 40 22 }

  condition:
    any of them
}