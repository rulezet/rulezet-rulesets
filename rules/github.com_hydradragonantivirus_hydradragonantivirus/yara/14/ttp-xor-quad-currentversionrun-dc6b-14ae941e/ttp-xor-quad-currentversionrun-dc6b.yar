rule TTP_XOR_QUAD_CurrentVersionRun_dc6b {
  strings:
    $key_dc6b = { 8f 04 [2] ab 0a [2] 80 26 [2] ae 04 [2] ba 1f [2] b5 05 [2] ab 18 [2] a9 19 [2] b2 1f [2] ae 18 [2] b2 37 }

  condition:
    any of them
}