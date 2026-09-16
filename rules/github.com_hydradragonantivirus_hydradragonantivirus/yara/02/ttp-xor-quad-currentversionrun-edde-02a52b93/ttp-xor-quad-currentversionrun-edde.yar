rule TTP_XOR_QUAD_CurrentVersionRun_edde {
  strings:
    $key_edde = { be b1 [2] 9a bf [2] b1 93 [2] 9f b1 [2] 8b aa [2] 84 b0 [2] 9a ad [2] 98 ac [2] 83 aa [2] 9f ad [2] 83 82 }

  condition:
    any of them
}