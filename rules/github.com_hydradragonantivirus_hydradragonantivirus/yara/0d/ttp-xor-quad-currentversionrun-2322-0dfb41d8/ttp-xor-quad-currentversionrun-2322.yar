rule TTP_XOR_QUAD_CurrentVersionRun_2322 {
  strings:
    $key_2322 = { 70 4d [2] 54 43 [2] 7f 6f [2] 51 4d [2] 45 56 [2] 4a 4c [2] 54 51 [2] 56 50 [2] 4d 56 [2] 51 51 [2] 4d 7e }

  condition:
    any of them
}