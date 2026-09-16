rule TTP_XOR_QUAD_CurrentVersionRun_d027 {
  strings:
    $key_d027 = { 83 48 [2] a7 46 [2] 8c 6a [2] a2 48 [2] b6 53 [2] b9 49 [2] a7 54 [2] a5 55 [2] be 53 [2] a2 54 [2] be 7b }

  condition:
    any of them
}