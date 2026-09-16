rule TTP_XOR_QUAD_CurrentVersionRun_571e {
  strings:
    $key_571e = { 04 71 [2] 20 7f [2] 0b 53 [2] 25 71 [2] 31 6a [2] 3e 70 [2] 20 6d [2] 22 6c [2] 39 6a [2] 25 6d [2] 39 42 }

  condition:
    any of them
}