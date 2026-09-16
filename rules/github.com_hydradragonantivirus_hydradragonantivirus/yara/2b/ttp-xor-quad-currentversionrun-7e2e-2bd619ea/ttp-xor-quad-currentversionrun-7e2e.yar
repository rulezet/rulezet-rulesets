rule TTP_XOR_QUAD_CurrentVersionRun_7e2e {
  strings:
    $key_7e2e = { 2d 41 [2] 09 4f [2] 22 63 [2] 0c 41 [2] 18 5a [2] 17 40 [2] 09 5d [2] 0b 5c [2] 10 5a [2] 0c 5d [2] 10 72 }

  condition:
    any of them
}