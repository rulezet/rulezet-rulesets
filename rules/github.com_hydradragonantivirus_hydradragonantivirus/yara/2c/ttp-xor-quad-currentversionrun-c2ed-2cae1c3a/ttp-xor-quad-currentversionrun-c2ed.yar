rule TTP_XOR_QUAD_CurrentVersionRun_c2ed {
  strings:
    $key_c2ed = { 91 82 [2] b5 8c [2] 9e a0 [2] b0 82 [2] a4 99 [2] ab 83 [2] b5 9e [2] b7 9f [2] ac 99 [2] b0 9e [2] ac b1 }

  condition:
    any of them
}