rule TTP_XOR_QUAD_CurrentVersionRun_011f {
  strings:
    $key_011f = { 52 70 [2] 76 7e [2] 5d 52 [2] 73 70 [2] 67 6b [2] 68 71 [2] 76 6c [2] 74 6d [2] 6f 6b [2] 73 6c [2] 6f 43 }

  condition:
    any of them
}