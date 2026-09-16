rule TTP_XOR_QUAD_CurrentVersionRun_11d9 {
  strings:
    $key_11d9 = { 42 b6 [2] 66 b8 [2] 4d 94 [2] 63 b6 [2] 77 ad [2] 78 b7 [2] 66 aa [2] 64 ab [2] 7f ad [2] 63 aa [2] 7f 85 }

  condition:
    any of them
}