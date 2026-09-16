rule TTP_XOR_QUAD_CurrentVersionRun_492e {
  strings:
    $key_492e = { 1a 41 [2] 3e 4f [2] 15 63 [2] 3b 41 [2] 2f 5a [2] 20 40 [2] 3e 5d [2] 3c 5c [2] 27 5a [2] 3b 5d [2] 27 72 }

  condition:
    any of them
}