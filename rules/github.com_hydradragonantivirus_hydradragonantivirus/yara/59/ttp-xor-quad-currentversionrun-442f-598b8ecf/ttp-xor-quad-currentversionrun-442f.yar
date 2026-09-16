rule TTP_XOR_QUAD_CurrentVersionRun_442f {
  strings:
    $key_442f = { 17 40 [2] 33 4e [2] 18 62 [2] 36 40 [2] 22 5b [2] 2d 41 [2] 33 5c [2] 31 5d [2] 2a 5b [2] 36 5c [2] 2a 73 }

  condition:
    any of them
}