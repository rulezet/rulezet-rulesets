rule TTP_XOR_MULT_DOSStub_61e3 {
  strings:
    $key_61e3 = { 35 8b [2] 41 93 [2] 06 91 [2] 41 80 [2] 0f 8c [2] 03 86 [2] 14 8d [2] 0f c3 [2] 32 }

  condition:
    any of them
}