rule TTP_XOR_QUAD_CurrentVersionRun_3362 {
  strings:
    $key_3362 = { 60 0d [2] 44 03 [2] 6f 2f [2] 41 0d [2] 55 16 [2] 5a 0c [2] 44 11 [2] 46 10 [2] 5d 16 [2] 41 11 [2] 5d 3e }

  condition:
    any of them
}