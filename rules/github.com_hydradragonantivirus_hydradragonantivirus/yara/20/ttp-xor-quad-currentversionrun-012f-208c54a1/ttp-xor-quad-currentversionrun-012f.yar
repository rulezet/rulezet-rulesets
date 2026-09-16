rule TTP_XOR_QUAD_CurrentVersionRun_012f {
  strings:
    $key_012f = { 52 40 [2] 76 4e [2] 5d 62 [2] 73 40 [2] 67 5b [2] 68 41 [2] 76 5c [2] 74 5d [2] 6f 5b [2] 73 5c [2] 6f 73 }

  condition:
    any of them
}