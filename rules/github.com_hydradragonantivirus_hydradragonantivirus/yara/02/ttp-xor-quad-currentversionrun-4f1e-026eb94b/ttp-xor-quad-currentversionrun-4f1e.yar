rule TTP_XOR_QUAD_CurrentVersionRun_4f1e {
  strings:
    $key_4f1e = { 1c 71 [2] 38 7f [2] 13 53 [2] 3d 71 [2] 29 6a [2] 26 70 [2] 38 6d [2] 3a 6c [2] 21 6a [2] 3d 6d [2] 21 42 }

  condition:
    any of them
}