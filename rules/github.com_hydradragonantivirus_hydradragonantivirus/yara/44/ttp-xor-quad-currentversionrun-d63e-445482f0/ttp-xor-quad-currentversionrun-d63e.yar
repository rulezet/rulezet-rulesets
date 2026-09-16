rule TTP_XOR_QUAD_CurrentVersionRun_d63e {
  strings:
    $key_d63e = { 85 51 [2] a1 5f [2] 8a 73 [2] a4 51 [2] b0 4a [2] bf 50 [2] a1 4d [2] a3 4c [2] b8 4a [2] a4 4d [2] b8 62 }

  condition:
    any of them
}