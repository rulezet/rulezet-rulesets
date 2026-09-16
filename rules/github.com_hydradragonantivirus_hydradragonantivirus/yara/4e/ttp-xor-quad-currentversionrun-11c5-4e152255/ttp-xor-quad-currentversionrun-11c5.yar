rule TTP_XOR_QUAD_CurrentVersionRun_11c5 {
  strings:
    $key_11c5 = { 42 aa [2] 66 a4 [2] 4d 88 [2] 63 aa [2] 77 b1 [2] 78 ab [2] 66 b6 [2] 64 b7 [2] 7f b1 [2] 63 b6 [2] 7f 99 }

  condition:
    any of them
}