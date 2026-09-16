rule TTP_XOR_MULT_DOSStub_61e5 {
  strings:
    $key_61e5 = { 35 8d [2] 41 95 [2] 06 97 [2] 41 86 [2] 0f 8a [2] 03 80 [2] 14 8b [2] 0f c5 [2] 32 }

  condition:
    any of them
}