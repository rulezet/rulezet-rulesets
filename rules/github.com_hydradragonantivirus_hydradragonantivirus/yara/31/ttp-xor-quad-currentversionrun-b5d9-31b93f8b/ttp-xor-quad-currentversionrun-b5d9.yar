rule TTP_XOR_QUAD_CurrentVersionRun_b5d9 {
  strings:
    $key_b5d9 = { e6 b6 [2] c2 b8 [2] e9 94 [2] c7 b6 [2] d3 ad [2] dc b7 [2] c2 aa [2] c0 ab [2] db ad [2] c7 aa [2] db 85 }

  condition:
    any of them
}