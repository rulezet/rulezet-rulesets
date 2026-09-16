rule TTP_XOR_QUAD_CurrentVersionRun_3351 {
  strings:
    $key_3351 = { 60 3e [2] 44 30 [2] 6f 1c [2] 41 3e [2] 55 25 [2] 5a 3f [2] 44 22 [2] 46 23 [2] 5d 25 [2] 41 22 [2] 5d 0d }

  condition:
    any of them
}