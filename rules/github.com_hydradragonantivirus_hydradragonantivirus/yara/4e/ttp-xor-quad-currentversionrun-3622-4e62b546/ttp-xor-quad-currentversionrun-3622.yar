rule TTP_XOR_QUAD_CurrentVersionRun_3622 {
  strings:
    $key_3622 = { 65 4d [2] 41 43 [2] 6a 6f [2] 44 4d [2] 50 56 [2] 5f 4c [2] 41 51 [2] 43 50 [2] 58 56 [2] 44 51 [2] 58 7e }

  condition:
    any of them
}