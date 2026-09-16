rule TTP_XOR_QUAD_CurrentVersionRun_c56b {
  strings:
    $key_c56b = { 96 04 [2] b2 0a [2] 99 26 [2] b7 04 [2] a3 1f [2] ac 05 [2] b2 18 [2] b0 19 [2] ab 1f [2] b7 18 [2] ab 37 }

  condition:
    any of them
}