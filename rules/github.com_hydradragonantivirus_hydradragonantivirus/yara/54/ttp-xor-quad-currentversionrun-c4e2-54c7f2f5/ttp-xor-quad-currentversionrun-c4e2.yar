rule TTP_XOR_QUAD_CurrentVersionRun_c4e2 {
  strings:
    $key_c4e2 = { 97 8d [2] b3 83 [2] 98 af [2] b6 8d [2] a2 96 [2] ad 8c [2] b3 91 [2] b1 90 [2] aa 96 [2] b6 91 [2] aa be }

  condition:
    any of them
}