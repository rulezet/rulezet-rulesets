rule TTP_XOR_QUAD_CurrentVersionRun_d7fe {
  strings:
    $key_d7fe = { 84 91 [2] a0 9f [2] 8b b3 [2] a5 91 [2] b1 8a [2] be 90 [2] a0 8d [2] a2 8c [2] b9 8a [2] a5 8d [2] b9 a2 }

  condition:
    any of them
}