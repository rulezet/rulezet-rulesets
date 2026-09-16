rule TTP_XOR_QUAD_CurrentVersionRun_c312 {
  strings:
    $key_c312 = { 90 7d [2] b4 73 [2] 9f 5f [2] b1 7d [2] a5 66 [2] aa 7c [2] b4 61 [2] b6 60 [2] ad 66 [2] b1 61 [2] ad 4e }

  condition:
    any of them
}