rule TTP_XOR_QUAD_CurrentVersionRun_621e {
  strings:
    $key_621e = { 31 71 [2] 15 7f [2] 3e 53 [2] 10 71 [2] 04 6a [2] 0b 70 [2] 15 6d [2] 17 6c [2] 0c 6a [2] 10 6d [2] 0c 42 }

  condition:
    any of them
}