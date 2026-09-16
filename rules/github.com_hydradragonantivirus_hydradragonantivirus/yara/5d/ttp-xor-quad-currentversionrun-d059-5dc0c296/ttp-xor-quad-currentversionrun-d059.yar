rule TTP_XOR_QUAD_CurrentVersionRun_d059 {
  strings:
    $key_d059 = { 83 36 [2] a7 38 [2] 8c 14 [2] a2 36 [2] b6 2d [2] b9 37 [2] a7 2a [2] a5 2b [2] be 2d [2] a2 2a [2] be 05 }

  condition:
    any of them
}