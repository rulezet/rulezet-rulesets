rule TTP_XOR_QUAD_CurrentVersionRun_57d9 {
  strings:
    $key_57d9 = { 04 b6 [2] 20 b8 [2] 0b 94 [2] 25 b6 [2] 31 ad [2] 3e b7 [2] 20 aa [2] 22 ab [2] 39 ad [2] 25 aa [2] 39 85 }

  condition:
    any of them
}