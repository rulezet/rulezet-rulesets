rule TTP_XOR_QUAD_CurrentVersionRun_2e2e {
  strings:
    $key_2e2e = { 7d 41 [2] 59 4f [2] 72 63 [2] 5c 41 [2] 48 5a [2] 47 40 [2] 59 5d [2] 5b 5c [2] 40 5a [2] 5c 5d [2] 40 72 }

  condition:
    any of them
}