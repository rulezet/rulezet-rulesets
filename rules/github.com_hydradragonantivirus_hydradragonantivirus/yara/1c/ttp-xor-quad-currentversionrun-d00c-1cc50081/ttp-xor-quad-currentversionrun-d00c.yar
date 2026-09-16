rule TTP_XOR_QUAD_CurrentVersionRun_d00c {
  strings:
    $key_d00c = { 83 63 [2] a7 6d [2] 8c 41 [2] a2 63 [2] b6 78 [2] b9 62 [2] a7 7f [2] a5 7e [2] be 78 [2] a2 7f [2] be 50 }

  condition:
    any of them
}