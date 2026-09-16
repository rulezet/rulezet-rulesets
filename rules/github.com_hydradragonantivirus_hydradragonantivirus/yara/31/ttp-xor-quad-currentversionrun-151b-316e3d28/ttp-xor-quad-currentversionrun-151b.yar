rule TTP_XOR_QUAD_CurrentVersionRun_151b {
  strings:
    $key_151b = { 46 74 [2] 62 7a [2] 49 56 [2] 67 74 [2] 73 6f [2] 7c 75 [2] 62 68 [2] 60 69 [2] 7b 6f [2] 67 68 [2] 7b 47 }

  condition:
    any of them
}