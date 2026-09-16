rule TTP_XOR_QUAD_CurrentVersionRun_c4eb {
  strings:
    $key_c4eb = { 97 84 [2] b3 8a [2] 98 a6 [2] b6 84 [2] a2 9f [2] ad 85 [2] b3 98 [2] b1 99 [2] aa 9f [2] b6 98 [2] aa b7 }

  condition:
    any of them
}