rule TTP_XOR_QUAD_CurrentVersionRun_dceb {
  strings:
    $key_dceb = { 8f 84 [2] ab 8a [2] 80 a6 [2] ae 84 [2] ba 9f [2] b5 85 [2] ab 98 [2] a9 99 [2] b2 9f [2] ae 98 [2] b2 b7 }

  condition:
    any of them
}