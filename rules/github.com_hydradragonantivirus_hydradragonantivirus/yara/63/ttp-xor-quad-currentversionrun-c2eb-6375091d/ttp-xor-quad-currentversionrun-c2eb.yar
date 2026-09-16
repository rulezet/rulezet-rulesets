rule TTP_XOR_QUAD_CurrentVersionRun_c2eb {
  strings:
    $key_c2eb = { 91 84 [2] b5 8a [2] 9e a6 [2] b0 84 [2] a4 9f [2] ab 85 [2] b5 98 [2] b7 99 [2] ac 9f [2] b0 98 [2] ac b7 }

  condition:
    any of them
}