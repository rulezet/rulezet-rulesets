rule TTP_XOR_QUAD_CurrentVersionRun_cbde {
  strings:
    $key_cbde = { 98 b1 [2] bc bf [2] 97 93 [2] b9 b1 [2] ad aa [2] a2 b0 [2] bc ad [2] be ac [2] a5 aa [2] b9 ad [2] a5 82 }

  condition:
    any of them
}