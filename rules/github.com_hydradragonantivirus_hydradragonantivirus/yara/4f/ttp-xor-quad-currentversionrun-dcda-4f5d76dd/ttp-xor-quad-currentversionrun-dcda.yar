rule TTP_XOR_QUAD_CurrentVersionRun_dcda {
  strings:
    $key_dcda = { 8f b5 [2] ab bb [2] 80 97 [2] ae b5 [2] ba ae [2] b5 b4 [2] ab a9 [2] a9 a8 [2] b2 ae [2] ae a9 [2] b2 86 }

  condition:
    any of them
}