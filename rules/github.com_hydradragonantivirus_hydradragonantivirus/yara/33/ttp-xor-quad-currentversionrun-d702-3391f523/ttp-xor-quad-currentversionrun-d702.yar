rule TTP_XOR_QUAD_CurrentVersionRun_d702 {
  strings:
    $key_d702 = { 84 6d [2] a0 63 [2] 8b 4f [2] a5 6d [2] b1 76 [2] be 6c [2] a0 71 [2] a2 70 [2] b9 76 [2] a5 71 [2] b9 5e }

  condition:
    any of them
}