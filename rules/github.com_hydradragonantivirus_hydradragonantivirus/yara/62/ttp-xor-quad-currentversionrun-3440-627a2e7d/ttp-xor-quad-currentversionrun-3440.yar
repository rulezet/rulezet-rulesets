rule TTP_XOR_QUAD_CurrentVersionRun_3440 {
  strings:
    $key_3440 = { 67 2f [2] 43 21 [2] 68 0d [2] 46 2f [2] 52 34 [2] 5d 2e [2] 43 33 [2] 41 32 [2] 5a 34 [2] 46 33 [2] 5a 1c }

  condition:
    any of them
}