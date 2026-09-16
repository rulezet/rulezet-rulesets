rule TTP_XOR_QUAD_CurrentVersionRun_ddd9 {
  strings:
    $key_ddd9 = { 8e b6 [2] aa b8 [2] 81 94 [2] af b6 [2] bb ad [2] b4 b7 [2] aa aa [2] a8 ab [2] b3 ad [2] af aa [2] b3 85 }

  condition:
    any of them
}