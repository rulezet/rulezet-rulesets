rule TTP_XOR_QUAD_CurrentVersionRun_d00e {
  strings:
    $key_d00e = { 83 61 [2] a7 6f [2] 8c 43 [2] a2 61 [2] b6 7a [2] b9 60 [2] a7 7d [2] a5 7c [2] be 7a [2] a2 7d [2] be 52 }

  condition:
    any of them
}