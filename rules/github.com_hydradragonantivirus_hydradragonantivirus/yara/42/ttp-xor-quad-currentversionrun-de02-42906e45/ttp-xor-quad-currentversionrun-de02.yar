rule TTP_XOR_QUAD_CurrentVersionRun_de02 {
  strings:
    $key_de02 = { 8d 6d [2] a9 63 [2] 82 4f [2] ac 6d [2] b8 76 [2] b7 6c [2] a9 71 [2] ab 70 [2] b0 76 [2] ac 71 [2] b0 5e }

  condition:
    any of them
}