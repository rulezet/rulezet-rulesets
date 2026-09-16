rule TTP_XOR_QUAD_CurrentVersionRun_c504 {
  strings:
    $key_c504 = { 96 6b [2] b2 65 [2] 99 49 [2] b7 6b [2] a3 70 [2] ac 6a [2] b2 77 [2] b0 76 [2] ab 70 [2] b7 77 [2] ab 58 }

  condition:
    any of them
}