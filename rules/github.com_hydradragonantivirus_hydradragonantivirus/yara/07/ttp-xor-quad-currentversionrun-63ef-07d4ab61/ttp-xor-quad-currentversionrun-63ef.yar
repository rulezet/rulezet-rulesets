rule TTP_XOR_QUAD_CurrentVersionRun_63ef {
  strings:
    $key_63ef = { 30 80 [2] 14 8e [2] 3f a2 [2] 11 80 [2] 05 9b [2] 0a 81 [2] 14 9c [2] 16 9d [2] 0d 9b [2] 11 9c [2] 0d b3 }

  condition:
    any of them
}