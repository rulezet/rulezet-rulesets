rule TTP_XOR_QUAD_CurrentVersionRun_fdde {
  strings:
    $key_fdde = { ae b1 [2] 8a bf [2] a1 93 [2] 8f b1 [2] 9b aa [2] 94 b0 [2] 8a ad [2] 88 ac [2] 93 aa [2] 8f ad [2] 93 82 }

  condition:
    any of them
}