rule TTP_XOR_QUAD_CurrentVersionRun_f6c5 {
  strings:
    $key_f6c5 = { a5 aa [2] 81 a4 [2] aa 88 [2] 84 aa [2] 90 b1 [2] 9f ab [2] 81 b6 [2] 83 b7 [2] 98 b1 [2] 84 b6 [2] 98 99 }

  condition:
    any of them
}