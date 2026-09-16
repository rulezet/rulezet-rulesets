rule TTP_XOR_QUAD_CurrentVersionRun_331e {
  strings:
    $key_331e = { 60 71 [2] 44 7f [2] 6f 53 [2] 41 71 [2] 55 6a [2] 5a 70 [2] 44 6d [2] 46 6c [2] 5d 6a [2] 41 6d [2] 5d 42 }

  condition:
    any of them
}