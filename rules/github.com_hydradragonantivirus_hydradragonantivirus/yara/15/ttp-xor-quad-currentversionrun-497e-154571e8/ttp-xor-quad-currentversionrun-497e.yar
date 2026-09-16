rule TTP_XOR_QUAD_CurrentVersionRun_497e {
  strings:
    $key_497e = { 1a 11 [2] 3e 1f [2] 15 33 [2] 3b 11 [2] 2f 0a [2] 20 10 [2] 3e 0d [2] 3c 0c [2] 27 0a [2] 3b 0d [2] 27 22 }

  condition:
    any of them
}