rule TTP_XOR_QUAD_CurrentVersionRun_c332 {
  strings:
    $key_c332 = { 90 5d [2] b4 53 [2] 9f 7f [2] b1 5d [2] a5 46 [2] aa 5c [2] b4 41 [2] b6 40 [2] ad 46 [2] b1 41 [2] ad 6e }

  condition:
    any of them
}