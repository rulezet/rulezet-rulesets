rule TTP_XOR_QUAD_CurrentVersionRun_2dde {
  strings:
    $key_2dde = { 7e b1 [2] 5a bf [2] 71 93 [2] 5f b1 [2] 4b aa [2] 44 b0 [2] 5a ad [2] 58 ac [2] 43 aa [2] 5f ad [2] 43 82 }

  condition:
    any of them
}