rule TTP_XOR_QUAD_CurrentVersionRun_d058 {
  strings:
    $key_d058 = { 83 37 [2] a7 39 [2] 8c 15 [2] a2 37 [2] b6 2c [2] b9 36 [2] a7 2b [2] a5 2a [2] be 2c [2] a2 2b [2] be 04 }

  condition:
    any of them
}