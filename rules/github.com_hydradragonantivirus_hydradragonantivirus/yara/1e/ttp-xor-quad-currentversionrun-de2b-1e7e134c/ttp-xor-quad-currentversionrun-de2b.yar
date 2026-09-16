rule TTP_XOR_QUAD_CurrentVersionRun_de2b {
  strings:
    $key_de2b = { 8d 44 [2] a9 4a [2] 82 66 [2] ac 44 [2] b8 5f [2] b7 45 [2] a9 58 [2] ab 59 [2] b0 5f [2] ac 58 [2] b0 77 }

  condition:
    any of them
}