rule TTP_XOR_QUAD_CurrentVersionRun_dcf8 {
  strings:
    $key_dcf8 = { 8f 97 [2] ab 99 [2] 80 b5 [2] ae 97 [2] ba 8c [2] b5 96 [2] ab 8b [2] a9 8a [2] b2 8c [2] ae 8b [2] b2 a4 }

  condition:
    any of them
}