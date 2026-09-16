rule TTP_XOR_QUAD_CurrentVersionRun_dcef {
  strings:
    $key_dcef = { 8f 80 [2] ab 8e [2] 80 a2 [2] ae 80 [2] ba 9b [2] b5 81 [2] ab 9c [2] a9 9d [2] b2 9b [2] ae 9c [2] b2 b3 }

  condition:
    any of them
}