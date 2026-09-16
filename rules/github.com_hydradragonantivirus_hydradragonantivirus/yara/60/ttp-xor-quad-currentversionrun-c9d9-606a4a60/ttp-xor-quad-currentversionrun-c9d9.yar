rule TTP_XOR_QUAD_CurrentVersionRun_c9d9 {
  strings:
    $key_c9d9 = { 9a b6 [2] be b8 [2] 95 94 [2] bb b6 [2] af ad [2] a0 b7 [2] be aa [2] bc ab [2] a7 ad [2] bb aa [2] a7 85 }

  condition:
    any of them
}