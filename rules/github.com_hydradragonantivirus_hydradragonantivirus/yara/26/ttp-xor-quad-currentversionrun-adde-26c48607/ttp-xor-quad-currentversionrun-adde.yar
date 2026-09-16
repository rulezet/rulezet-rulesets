rule TTP_XOR_QUAD_CurrentVersionRun_adde {
  strings:
    $key_adde = { fe b1 [2] da bf [2] f1 93 [2] df b1 [2] cb aa [2] c4 b0 [2] da ad [2] d8 ac [2] c3 aa [2] df ad [2] c3 82 }

  condition:
    any of them
}