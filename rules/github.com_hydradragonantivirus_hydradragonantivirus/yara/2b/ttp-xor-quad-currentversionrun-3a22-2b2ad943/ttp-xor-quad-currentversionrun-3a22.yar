rule TTP_XOR_QUAD_CurrentVersionRun_3a22 {
  strings:
    $key_3a22 = { 69 4d [2] 4d 43 [2] 66 6f [2] 48 4d [2] 5c 56 [2] 53 4c [2] 4d 51 [2] 4f 50 [2] 54 56 [2] 48 51 [2] 54 7e }

  condition:
    any of them
}