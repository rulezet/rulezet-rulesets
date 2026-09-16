rule TTP_XOR_QUAD_CurrentVersionRun_011e {
  strings:
    $key_011e = { 52 71 [2] 76 7f [2] 5d 53 [2] 73 71 [2] 67 6a [2] 68 70 [2] 76 6d [2] 74 6c [2] 6f 6a [2] 73 6d [2] 6f 42 }

  condition:
    any of them
}