rule TTP_XOR_QUAD_CurrentVersionRun_501e {
  strings:
    $key_501e = { 03 71 [2] 27 7f [2] 0c 53 [2] 22 71 [2] 36 6a [2] 39 70 [2] 27 6d [2] 25 6c [2] 3e 6a [2] 22 6d [2] 3e 42 }

  condition:
    any of them
}