rule TTP_XOR_QUAD_CurrentVersionRun_c428 {
  strings:
    $key_c428 = { 97 47 [2] b3 49 [2] 98 65 [2] b6 47 [2] a2 5c [2] ad 46 [2] b3 5b [2] b1 5a [2] aa 5c [2] b6 5b [2] aa 74 }

  condition:
    any of them
}