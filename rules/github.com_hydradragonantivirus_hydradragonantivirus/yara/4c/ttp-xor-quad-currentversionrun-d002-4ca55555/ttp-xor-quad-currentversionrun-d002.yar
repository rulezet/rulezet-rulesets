rule TTP_XOR_QUAD_CurrentVersionRun_d002 {
  strings:
    $key_d002 = { 83 6d [2] a7 63 [2] 8c 4f [2] a2 6d [2] b6 76 [2] b9 6c [2] a7 71 [2] a5 70 [2] be 76 [2] a2 71 [2] be 5e }

  condition:
    any of them
}