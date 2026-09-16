rule TTP_XOR_MULT_DOSStub_c502 {
  strings:
    $key_c502 = { 91 6a [2] e5 72 [2] a2 70 [2] e5 61 [2] ab 6d [2] a7 67 [2] b0 6c [2] ab 22 [2] 96 }

  condition:
    any of them
}