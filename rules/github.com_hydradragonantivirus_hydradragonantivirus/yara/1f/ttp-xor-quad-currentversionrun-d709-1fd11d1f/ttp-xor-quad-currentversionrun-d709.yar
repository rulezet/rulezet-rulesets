rule TTP_XOR_QUAD_CurrentVersionRun_d709 {
  strings:
    $key_d709 = { 84 66 [2] a0 68 [2] 8b 44 [2] a5 66 [2] b1 7d [2] be 67 [2] a0 7a [2] a2 7b [2] b9 7d [2] a5 7a [2] b9 55 }

  condition:
    any of them
}