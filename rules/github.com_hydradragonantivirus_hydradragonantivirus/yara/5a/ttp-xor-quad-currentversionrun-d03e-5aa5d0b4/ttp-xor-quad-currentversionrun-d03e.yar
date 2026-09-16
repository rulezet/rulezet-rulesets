rule TTP_XOR_QUAD_CurrentVersionRun_d03e {
  strings:
    $key_d03e = { 83 51 [2] a7 5f [2] 8c 73 [2] a2 51 [2] b6 4a [2] b9 50 [2] a7 4d [2] a5 4c [2] be 4a [2] a2 4d [2] be 62 }

  condition:
    any of them
}