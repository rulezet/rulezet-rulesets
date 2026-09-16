rule TTP_XOR_QUAD_CurrentVersionRun_d856 {
  strings:
    $key_d856 = { 8b 39 [2] af 37 [2] 84 1b [2] aa 39 [2] be 22 [2] b1 38 [2] af 25 [2] ad 24 [2] b6 22 [2] aa 25 [2] b6 0a }

  condition:
    any of them
}