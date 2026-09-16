rule TTP_XOR_QUAD_CurrentVersionRun_3a1e {
  strings:
    $key_3a1e = { 69 71 [2] 4d 7f [2] 66 53 [2] 48 71 [2] 5c 6a [2] 53 70 [2] 4d 6d [2] 4f 6c [2] 54 6a [2] 48 6d [2] 54 42 }

  condition:
    any of them
}