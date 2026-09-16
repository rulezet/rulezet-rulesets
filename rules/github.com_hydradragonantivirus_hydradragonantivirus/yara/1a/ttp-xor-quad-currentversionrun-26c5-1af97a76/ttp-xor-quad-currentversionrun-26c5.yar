rule TTP_XOR_QUAD_CurrentVersionRun_26c5 {
  strings:
    $key_26c5 = { 75 aa [2] 51 a4 [2] 7a 88 [2] 54 aa [2] 40 b1 [2] 4f ab [2] 51 b6 [2] 53 b7 [2] 48 b1 [2] 54 b6 [2] 48 99 }

  condition:
    any of them
}