rule TTP_XOR_QUAD_CurrentVersionRun_4dde {
  strings:
    $key_4dde = { 1e b1 [2] 3a bf [2] 11 93 [2] 3f b1 [2] 2b aa [2] 24 b0 [2] 3a ad [2] 38 ac [2] 23 aa [2] 3f ad [2] 23 82 }

  condition:
    any of them
}