rule TTP_XOR_QUAD_CurrentVersionRun_23c5 {
  strings:
    $key_23c5 = { 70 aa [2] 54 a4 [2] 7f 88 [2] 51 aa [2] 45 b1 [2] 4a ab [2] 54 b6 [2] 56 b7 [2] 4d b1 [2] 51 b6 [2] 4d 99 }

  condition:
    any of them
}