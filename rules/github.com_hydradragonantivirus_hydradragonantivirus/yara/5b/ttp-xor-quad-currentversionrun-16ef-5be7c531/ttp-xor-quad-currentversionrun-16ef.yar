rule TTP_XOR_QUAD_CurrentVersionRun_16ef {
  strings:
    $key_16ef = { 45 80 [2] 61 8e [2] 4a a2 [2] 64 80 [2] 70 9b [2] 7f 81 [2] 61 9c [2] 63 9d [2] 78 9b [2] 64 9c [2] 78 b3 }

  condition:
    any of them
}