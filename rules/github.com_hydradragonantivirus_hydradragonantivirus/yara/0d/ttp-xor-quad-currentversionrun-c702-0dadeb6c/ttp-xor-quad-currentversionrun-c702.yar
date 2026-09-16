rule TTP_XOR_QUAD_CurrentVersionRun_c702 {
  strings:
    $key_c702 = { 94 6d [2] b0 63 [2] 9b 4f [2] b5 6d [2] a1 76 [2] ae 6c [2] b0 71 [2] b2 70 [2] a9 76 [2] b5 71 [2] a9 5e }

  condition:
    any of them
}