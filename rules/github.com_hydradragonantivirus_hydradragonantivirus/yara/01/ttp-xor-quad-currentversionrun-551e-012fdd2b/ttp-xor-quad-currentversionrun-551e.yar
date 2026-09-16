rule TTP_XOR_QUAD_CurrentVersionRun_551e {
  strings:
    $key_551e = { 06 71 [2] 22 7f [2] 09 53 [2] 27 71 [2] 33 6a [2] 3c 70 [2] 22 6d [2] 20 6c [2] 3b 6a [2] 27 6d [2] 3b 42 }

  condition:
    any of them
}