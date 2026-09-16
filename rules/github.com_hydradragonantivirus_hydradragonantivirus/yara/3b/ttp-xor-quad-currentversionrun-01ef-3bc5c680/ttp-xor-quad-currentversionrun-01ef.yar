rule TTP_XOR_QUAD_CurrentVersionRun_01ef {
  strings:
    $key_01ef = { 52 80 [2] 76 8e [2] 5d a2 [2] 73 80 [2] 67 9b [2] 68 81 [2] 76 9c [2] 74 9d [2] 6f 9b [2] 73 9c [2] 6f b3 }

  condition:
    any of them
}