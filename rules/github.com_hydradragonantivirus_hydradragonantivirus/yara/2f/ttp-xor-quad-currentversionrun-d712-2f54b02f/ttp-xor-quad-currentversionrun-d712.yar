rule TTP_XOR_QUAD_CurrentVersionRun_d712 {
  strings:
    $key_d712 = { 84 7d [2] a0 73 [2] 8b 5f [2] a5 7d [2] b1 66 [2] be 7c [2] a0 61 [2] a2 60 [2] b9 66 [2] a5 61 [2] b9 4e }

  condition:
    any of them
}