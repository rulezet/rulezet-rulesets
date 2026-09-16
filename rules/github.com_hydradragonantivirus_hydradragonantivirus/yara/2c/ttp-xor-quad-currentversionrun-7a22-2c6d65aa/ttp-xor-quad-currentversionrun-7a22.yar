rule TTP_XOR_QUAD_CurrentVersionRun_7a22 {
  strings:
    $key_7a22 = { 29 4d [2] 0d 43 [2] 26 6f [2] 08 4d [2] 1c 56 [2] 13 4c [2] 0d 51 [2] 0f 50 [2] 14 56 [2] 08 51 [2] 14 7e }

  condition:
    any of them
}