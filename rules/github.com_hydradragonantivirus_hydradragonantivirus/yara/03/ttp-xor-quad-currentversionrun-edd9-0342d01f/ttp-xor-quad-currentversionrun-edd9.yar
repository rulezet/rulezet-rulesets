rule TTP_XOR_QUAD_CurrentVersionRun_edd9 {
  strings:
    $key_edd9 = { be b6 [2] 9a b8 [2] b1 94 [2] 9f b6 [2] 8b ad [2] 84 b7 [2] 9a aa [2] 98 ab [2] 83 ad [2] 9f aa [2] 83 85 }

  condition:
    any of them
}