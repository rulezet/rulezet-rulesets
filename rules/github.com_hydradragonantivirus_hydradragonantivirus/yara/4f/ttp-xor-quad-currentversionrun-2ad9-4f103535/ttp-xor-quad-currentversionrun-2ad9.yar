rule TTP_XOR_QUAD_CurrentVersionRun_2ad9 {
  strings:
    $key_2ad9 = { 79 b6 [2] 5d b8 [2] 76 94 [2] 58 b6 [2] 4c ad [2] 43 b7 [2] 5d aa [2] 5f ab [2] 44 ad [2] 58 aa [2] 44 85 }

  condition:
    any of them
}