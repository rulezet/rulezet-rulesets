rule TTP_XOR_QUAD_CurrentVersionRun_30c5 {
  strings:
    $key_30c5 = { 63 aa [2] 47 a4 [2] 6c 88 [2] 42 aa [2] 56 b1 [2] 59 ab [2] 47 b6 [2] 45 b7 [2] 5e b1 [2] 42 b6 [2] 5e 99 }

  condition:
    any of them
}