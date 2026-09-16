rule TTP_XOR_QUAD_CurrentVersionRun_ccc7 {
  strings:
    $key_ccc7 = { 9f a8 [2] bb a6 [2] 90 8a [2] be a8 [2] aa b3 [2] a5 a9 [2] bb b4 [2] b9 b5 [2] a2 b3 [2] be b4 [2] a2 9b }

  condition:
    any of them
}