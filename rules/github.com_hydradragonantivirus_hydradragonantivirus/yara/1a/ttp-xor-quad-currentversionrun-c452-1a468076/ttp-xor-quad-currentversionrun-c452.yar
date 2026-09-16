rule TTP_XOR_QUAD_CurrentVersionRun_c452 {
  strings:
    $key_c452 = { 97 3d [2] b3 33 [2] 98 1f [2] b6 3d [2] a2 26 [2] ad 3c [2] b3 21 [2] b1 20 [2] aa 26 [2] b6 21 [2] aa 0e }

  condition:
    any of them
}