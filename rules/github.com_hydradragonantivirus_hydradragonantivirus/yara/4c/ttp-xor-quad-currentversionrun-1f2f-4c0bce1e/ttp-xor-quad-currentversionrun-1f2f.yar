rule TTP_XOR_QUAD_CurrentVersionRun_1f2f {
  strings:
    $key_1f2f = { 4c 40 [2] 68 4e [2] 43 62 [2] 6d 40 [2] 79 5b [2] 76 41 [2] 68 5c [2] 6a 5d [2] 71 5b [2] 6d 5c [2] 71 73 }

  condition:
    any of them
}