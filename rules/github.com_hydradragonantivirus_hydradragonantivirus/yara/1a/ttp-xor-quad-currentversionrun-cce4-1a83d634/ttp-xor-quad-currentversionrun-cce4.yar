rule TTP_XOR_QUAD_CurrentVersionRun_cce4 {
  strings:
    $key_cce4 = { 9f 8b [2] bb 85 [2] 90 a9 [2] be 8b [2] aa 90 [2] a5 8a [2] bb 97 [2] b9 96 [2] a2 90 [2] be 97 [2] a2 b8 }

  condition:
    any of them
}