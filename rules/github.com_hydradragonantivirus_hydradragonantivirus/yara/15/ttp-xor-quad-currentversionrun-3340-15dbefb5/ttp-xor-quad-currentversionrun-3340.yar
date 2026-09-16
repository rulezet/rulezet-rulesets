rule TTP_XOR_QUAD_CurrentVersionRun_3340 {
  strings:
    $key_3340 = { 60 2f [2] 44 21 [2] 6f 0d [2] 41 2f [2] 55 34 [2] 5a 2e [2] 44 33 [2] 46 32 [2] 5d 34 [2] 41 33 [2] 5d 1c }

  condition:
    any of them
}