rule TTP_XOR_QUAD_CurrentVersionRun_33ef {
  strings:
    $key_33ef = { 60 80 [2] 44 8e [2] 6f a2 [2] 41 80 [2] 55 9b [2] 5a 81 [2] 44 9c [2] 46 9d [2] 5d 9b [2] 41 9c [2] 5d b3 }

  condition:
    any of them
}