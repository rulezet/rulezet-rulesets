rule TTP_XOR_QUAD_CurrentVersionRun_de2a {
  strings:
    $key_de2a = { 8d 45 [2] a9 4b [2] 82 67 [2] ac 45 [2] b8 5e [2] b7 44 [2] a9 59 [2] ab 58 [2] b0 5e [2] ac 59 [2] b0 76 }

  condition:
    any of them
}