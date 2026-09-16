rule TTP_XOR_QUAD_CurrentVersionRun_c317 {
  strings:
    $key_c317 = { 90 78 [2] b4 76 [2] 9f 5a [2] b1 78 [2] a5 63 [2] aa 79 [2] b4 64 [2] b6 65 [2] ad 63 [2] b1 64 [2] ad 4b }

  condition:
    any of them
}