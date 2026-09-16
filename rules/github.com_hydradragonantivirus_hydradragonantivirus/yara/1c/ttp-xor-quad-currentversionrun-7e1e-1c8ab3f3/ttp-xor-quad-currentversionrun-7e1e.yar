rule TTP_XOR_QUAD_CurrentVersionRun_7e1e {
  strings:
    $key_7e1e = { 2d 71 [2] 09 7f [2] 22 53 [2] 0c 71 [2] 18 6a [2] 17 70 [2] 09 6d [2] 0b 6c [2] 10 6a [2] 0c 6d [2] 10 42 }

  condition:
    any of them
}