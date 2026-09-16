rule TTP_XOR_QUAD_CurrentVersionRun_ccd6 {
  strings:
    $key_ccd6 = { 9f b9 [2] bb b7 [2] 90 9b [2] be b9 [2] aa a2 [2] a5 b8 [2] bb a5 [2] b9 a4 [2] a2 a2 [2] be a5 [2] a2 8a }

  condition:
    any of them
}