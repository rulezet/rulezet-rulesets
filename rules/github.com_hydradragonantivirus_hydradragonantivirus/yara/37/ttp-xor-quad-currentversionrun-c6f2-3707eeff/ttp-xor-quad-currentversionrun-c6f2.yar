rule TTP_XOR_QUAD_CurrentVersionRun_c6f2 {
  strings:
    $key_c6f2 = { 95 9d [2] b1 93 [2] 9a bf [2] b4 9d [2] a0 86 [2] af 9c [2] b1 81 [2] b3 80 [2] a8 86 [2] b4 81 [2] a8 ae }

  condition:
    any of them
}