rule TTP_XOR_QUAD_CurrentVersionRun_11d8 {
  strings:
    $key_11d8 = { 42 b7 [2] 66 b9 [2] 4d 95 [2] 63 b7 [2] 77 ac [2] 78 b6 [2] 66 ab [2] 64 aa [2] 7f ac [2] 63 ab [2] 7f 84 }

  condition:
    any of them
}