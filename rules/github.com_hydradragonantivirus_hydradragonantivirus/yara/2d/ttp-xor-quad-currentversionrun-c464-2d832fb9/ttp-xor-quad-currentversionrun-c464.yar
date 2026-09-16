rule TTP_XOR_QUAD_CurrentVersionRun_c464 {
  strings:
    $key_c464 = { 97 0b [2] b3 05 [2] 98 29 [2] b6 0b [2] a2 10 [2] ad 0a [2] b3 17 [2] b1 16 [2] aa 10 [2] b6 17 [2] aa 38 }

  condition:
    any of them
}