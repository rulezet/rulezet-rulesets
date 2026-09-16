rule TTP_XOR_QUAD_CurrentVersionRun_6dde {
  strings:
    $key_6dde = { 3e b1 [2] 1a bf [2] 31 93 [2] 1f b1 [2] 0b aa [2] 04 b0 [2] 1a ad [2] 18 ac [2] 03 aa [2] 1f ad [2] 03 82 }

  condition:
    any of them
}