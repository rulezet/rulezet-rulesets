rule TTP_XOR_QUAD_CurrentVersionRun_e729 {
  strings:
    $key_e729 = { b4 46 [2] 90 48 [2] bb 64 [2] 95 46 [2] 81 5d [2] 8e 47 [2] 90 5a [2] 92 5b [2] 89 5d [2] 95 5a [2] 89 75 }

  condition:
    any of them
}