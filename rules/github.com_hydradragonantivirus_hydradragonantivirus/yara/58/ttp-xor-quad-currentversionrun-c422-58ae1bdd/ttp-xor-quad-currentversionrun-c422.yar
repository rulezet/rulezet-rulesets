rule TTP_XOR_QUAD_CurrentVersionRun_c422 {
  strings:
    $key_c422 = { 97 4d [2] b3 43 [2] 98 6f [2] b6 4d [2] a2 56 [2] ad 4c [2] b3 51 [2] b1 50 [2] aa 56 [2] b6 51 [2] aa 7e }

  condition:
    any of them
}