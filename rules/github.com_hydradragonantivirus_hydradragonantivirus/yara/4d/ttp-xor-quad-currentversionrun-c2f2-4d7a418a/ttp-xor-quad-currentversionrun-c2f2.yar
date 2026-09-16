rule TTP_XOR_QUAD_CurrentVersionRun_c2f2 {
  strings:
    $key_c2f2 = { 91 9d [2] b5 93 [2] 9e bf [2] b0 9d [2] a4 86 [2] ab 9c [2] b5 81 [2] b7 80 [2] ac 86 [2] b0 81 [2] ac ae }

  condition:
    any of them
}