rule TTP_XOR_QUAD_CurrentVersionRun_1ad9 {
  strings:
    $key_1ad9 = { 49 b6 [2] 6d b8 [2] 46 94 [2] 68 b6 [2] 7c ad [2] 73 b7 [2] 6d aa [2] 6f ab [2] 74 ad [2] 68 aa [2] 74 85 }

  condition:
    any of them
}