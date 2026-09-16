rule TTP_XOR_QUAD_CurrentVersionRun_11c4 {
  strings:
    $key_11c4 = { 42 ab [2] 66 a5 [2] 4d 89 [2] 63 ab [2] 77 b0 [2] 78 aa [2] 66 b7 [2] 64 b6 [2] 7f b0 [2] 63 b7 [2] 7f 98 }

  condition:
    any of them
}