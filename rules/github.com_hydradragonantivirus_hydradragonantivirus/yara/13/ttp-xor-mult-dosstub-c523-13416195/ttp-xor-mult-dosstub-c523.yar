rule TTP_XOR_MULT_DOSStub_c523 {
  strings:
    $key_c523 = { 91 4b [2] e5 53 [2] a2 51 [2] e5 40 [2] ab 4c [2] a7 46 [2] b0 4d [2] ab 03 [2] 96 }

  condition:
    any of them
}