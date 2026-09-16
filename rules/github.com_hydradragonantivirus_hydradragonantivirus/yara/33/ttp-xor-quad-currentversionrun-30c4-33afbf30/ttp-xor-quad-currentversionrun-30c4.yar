rule TTP_XOR_QUAD_CurrentVersionRun_30c4 {
  strings:
    $key_30c4 = { 63 ab [2] 47 a5 [2] 6c 89 [2] 42 ab [2] 56 b0 [2] 59 aa [2] 47 b7 [2] 45 b6 [2] 5e b0 [2] 42 b7 [2] 5e 98 }

  condition:
    any of them
}