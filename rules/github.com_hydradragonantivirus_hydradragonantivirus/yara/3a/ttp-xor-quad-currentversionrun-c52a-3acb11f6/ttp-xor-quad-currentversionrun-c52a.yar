rule TTP_XOR_QUAD_CurrentVersionRun_c52a {
  strings:
    $key_c52a = { 96 45 [2] b2 4b [2] 99 67 [2] b7 45 [2] a3 5e [2] ac 44 [2] b2 59 [2] b0 58 [2] ab 5e [2] b7 59 [2] ab 76 }

  condition:
    any of them
}