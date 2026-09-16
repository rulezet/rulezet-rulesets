rule TTP_XOR_QUAD_CurrentVersionRun_d8de {
  strings:
    $key_d8de = { 8b b1 [2] af bf [2] 84 93 [2] aa b1 [2] be aa [2] b1 b0 [2] af ad [2] ad ac [2] b6 aa [2] aa ad [2] b6 82 }

  condition:
    any of them
}