rule TTP_XOR_QUAD_CurrentVersionRun_c314 {
  strings:
    $key_c314 = { 90 7b [2] b4 75 [2] 9f 59 [2] b1 7b [2] a5 60 [2] aa 7a [2] b4 67 [2] b6 66 [2] ad 60 [2] b1 67 [2] ad 48 }

  condition:
    any of them
}