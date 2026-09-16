rule TTP_XOR_QUAD_CurrentVersionRun_cfd9 {
  strings:
    $key_cfd9 = { 9c b6 [2] b8 b8 [2] 93 94 [2] bd b6 [2] a9 ad [2] a6 b7 [2] b8 aa [2] ba ab [2] a1 ad [2] bd aa [2] a1 85 }

  condition:
    any of them
}