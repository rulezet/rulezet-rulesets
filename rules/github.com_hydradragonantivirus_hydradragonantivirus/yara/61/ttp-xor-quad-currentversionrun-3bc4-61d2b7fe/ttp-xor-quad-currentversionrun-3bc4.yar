rule TTP_XOR_QUAD_CurrentVersionRun_3bc4 {
  strings:
    $key_3bc4 = { 68 ab [2] 4c a5 [2] 67 89 [2] 49 ab [2] 5d b0 [2] 52 aa [2] 4c b7 [2] 4e b6 [2] 55 b0 [2] 49 b7 [2] 55 98 }

  condition:
    any of them
}