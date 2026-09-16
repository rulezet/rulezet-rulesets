rule TTP_XOR_QUAD_CurrentVersionRun_0ad9 {
  strings:
    $key_0ad9 = { 59 b6 [2] 7d b8 [2] 56 94 [2] 78 b6 [2] 6c ad [2] 63 b7 [2] 7d aa [2] 7f ab [2] 64 ad [2] 78 aa [2] 64 85 }

  condition:
    any of them
}