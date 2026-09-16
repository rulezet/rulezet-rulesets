rule TTP_XOR_MULT_DOSStub_c528 {
  strings:
    $key_c528 = { 91 40 [2] e5 58 [2] a2 5a [2] e5 4b [2] ab 47 [2] a7 4d [2] b0 46 [2] ab 08 [2] 96 }

  condition:
    any of them
}