rule TTP_XOR_QUAD_CurrentVersionRun_3330 {
  strings:
    $key_3330 = { 60 5f [2] 44 51 [2] 6f 7d [2] 41 5f [2] 55 44 [2] 5a 5e [2] 44 43 [2] 46 42 [2] 5d 44 [2] 41 43 [2] 5d 6c }

  condition:
    any of them
}