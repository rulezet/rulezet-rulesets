rule TTP_XOR_QUAD_CurrentVersionRun_dcf9 {
  strings:
    $key_dcf9 = { 8f 96 [2] ab 98 [2] 80 b4 [2] ae 96 [2] ba 8d [2] b5 97 [2] ab 8a [2] a9 8b [2] b2 8d [2] ae 8a [2] b2 a5 }

  condition:
    any of them
}