rule TTP_XOR_QUAD_CurrentVersionRun_2d22 {
  strings:
    $key_2d22 = { 7e 4d [2] 5a 43 [2] 71 6f [2] 5f 4d [2] 4b 56 [2] 44 4c [2] 5a 51 [2] 58 50 [2] 43 56 [2] 5f 51 [2] 43 7e }

  condition:
    any of them
}