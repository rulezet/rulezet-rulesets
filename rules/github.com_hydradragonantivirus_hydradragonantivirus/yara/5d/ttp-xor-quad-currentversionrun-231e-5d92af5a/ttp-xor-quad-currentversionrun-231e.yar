rule TTP_XOR_QUAD_CurrentVersionRun_231e {
  strings:
    $key_231e = { 70 71 [2] 54 7f [2] 7f 53 [2] 51 71 [2] 45 6a [2] 4a 70 [2] 54 6d [2] 56 6c [2] 4d 6a [2] 51 6d [2] 4d 42 }

  condition:
    any of them
}