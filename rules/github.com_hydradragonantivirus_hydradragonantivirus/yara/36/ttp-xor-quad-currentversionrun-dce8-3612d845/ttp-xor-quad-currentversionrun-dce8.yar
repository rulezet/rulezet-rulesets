rule TTP_XOR_QUAD_CurrentVersionRun_dce8 {
  strings:
    $key_dce8 = { 8f 87 [2] ab 89 [2] 80 a5 [2] ae 87 [2] ba 9c [2] b5 86 [2] ab 9b [2] a9 9a [2] b2 9c [2] ae 9b [2] b2 b4 }

  condition:
    any of them
}