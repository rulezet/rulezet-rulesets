rule TTP_XOR_QUAD_CurrentVersionRun_d011 {
  strings:
    $key_d011 = { 83 7e [2] a7 70 [2] 8c 5c [2] a2 7e [2] b6 65 [2] b9 7f [2] a7 62 [2] a5 63 [2] be 65 [2] a2 62 [2] be 4d }

  condition:
    any of them
}