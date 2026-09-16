rule TTP_XOR_QUAD_CurrentVersionRun_ccc6 {
  strings:
    $key_ccc6 = { 9f a9 [2] bb a7 [2] 90 8b [2] be a9 [2] aa b2 [2] a5 a8 [2] bb b5 [2] b9 b4 [2] a2 b2 [2] be b5 [2] a2 9a }

  condition:
    any of them
}