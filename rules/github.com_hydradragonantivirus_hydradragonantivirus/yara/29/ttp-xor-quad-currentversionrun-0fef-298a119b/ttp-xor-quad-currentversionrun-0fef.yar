rule TTP_XOR_QUAD_CurrentVersionRun_0fef {
  strings:
    $key_0fef = { 5c 80 [2] 78 8e [2] 53 a2 [2] 7d 80 [2] 69 9b [2] 66 81 [2] 78 9c [2] 7a 9d [2] 61 9b [2] 7d 9c [2] 61 b3 }

  condition:
    any of them
}