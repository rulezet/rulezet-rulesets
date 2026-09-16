rule TTP_XOR_QUAD_CurrentVersionRun_5ad9 {
  strings:
    $key_5ad9 = { 09 b6 [2] 2d b8 [2] 06 94 [2] 28 b6 [2] 3c ad [2] 33 b7 [2] 2d aa [2] 2f ab [2] 34 ad [2] 28 aa [2] 34 85 }

  condition:
    any of them
}