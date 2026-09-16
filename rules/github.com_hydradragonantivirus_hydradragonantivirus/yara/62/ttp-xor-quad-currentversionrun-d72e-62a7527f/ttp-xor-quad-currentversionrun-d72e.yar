rule TTP_XOR_QUAD_CurrentVersionRun_d72e {
  strings:
    $key_d72e = { 84 41 [2] a0 4f [2] 8b 63 [2] a5 41 [2] b1 5a [2] be 40 [2] a0 5d [2] a2 5c [2] b9 5a [2] a5 5d [2] b9 72 }

  condition:
    any of them
}