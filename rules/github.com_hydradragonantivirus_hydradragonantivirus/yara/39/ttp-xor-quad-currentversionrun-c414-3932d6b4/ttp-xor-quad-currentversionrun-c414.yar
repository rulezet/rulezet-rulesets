rule TTP_XOR_QUAD_CurrentVersionRun_c414 {
  strings:
    $key_c414 = { 97 7b [2] b3 75 [2] 98 59 [2] b6 7b [2] a2 60 [2] ad 7a [2] b3 67 [2] b1 66 [2] aa 60 [2] b6 67 [2] aa 48 }

  condition:
    any of them
}