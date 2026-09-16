rule TTP_XOR_QUAD_CurrentVersionRun_12c5 {
  strings:
    $key_12c5 = { 41 aa [2] 65 a4 [2] 4e 88 [2] 60 aa [2] 74 b1 [2] 7b ab [2] 65 b6 [2] 67 b7 [2] 7c b1 [2] 60 b6 [2] 7c 99 }

  condition:
    any of them
}