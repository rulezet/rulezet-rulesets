rule TTP_XOR_QUAD_CurrentVersionRun_5dde {
  strings:
    $key_5dde = { 0e b1 [2] 2a bf [2] 01 93 [2] 2f b1 [2] 3b aa [2] 34 b0 [2] 2a ad [2] 28 ac [2] 33 aa [2] 2f ad [2] 33 82 }

  condition:
    any of them
}