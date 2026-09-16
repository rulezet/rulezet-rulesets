rule TTP_XOR_QUAD_CurrentVersionRun_181e {
  strings:
    $key_181e = { 4b 71 [2] 6f 7f [2] 44 53 [2] 6a 71 [2] 7e 6a [2] 71 70 [2] 6f 6d [2] 6d 6c [2] 76 6a [2] 6a 6d [2] 76 42 }

  condition:
    any of them
}