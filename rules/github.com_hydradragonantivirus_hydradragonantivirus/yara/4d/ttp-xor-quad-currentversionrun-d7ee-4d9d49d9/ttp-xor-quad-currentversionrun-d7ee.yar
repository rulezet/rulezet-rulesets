rule TTP_XOR_QUAD_CurrentVersionRun_d7ee {
  strings:
    $key_d7ee = { 84 81 [2] a0 8f [2] 8b a3 [2] a5 81 [2] b1 9a [2] be 80 [2] a0 9d [2] a2 9c [2] b9 9a [2] a5 9d [2] b9 b2 }

  condition:
    any of them
}