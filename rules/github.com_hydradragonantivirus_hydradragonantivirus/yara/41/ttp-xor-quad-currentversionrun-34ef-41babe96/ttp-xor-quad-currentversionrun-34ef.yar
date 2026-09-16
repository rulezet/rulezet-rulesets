rule TTP_XOR_QUAD_CurrentVersionRun_34ef {
  strings:
    $key_34ef = { 67 80 [2] 43 8e [2] 68 a2 [2] 46 80 [2] 52 9b [2] 5d 81 [2] 43 9c [2] 41 9d [2] 5a 9b [2] 46 9c [2] 5a b3 }

  condition:
    any of them
}