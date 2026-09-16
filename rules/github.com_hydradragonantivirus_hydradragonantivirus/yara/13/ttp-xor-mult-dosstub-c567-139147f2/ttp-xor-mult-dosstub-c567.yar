rule TTP_XOR_MULT_DOSStub_c567 {
  strings:
    $key_c567 = { 91 0f [2] e5 17 [2] a2 15 [2] e5 04 [2] ab 08 [2] a7 02 [2] b0 09 [2] ab 47 [2] 96 }

  condition:
    any of them
}