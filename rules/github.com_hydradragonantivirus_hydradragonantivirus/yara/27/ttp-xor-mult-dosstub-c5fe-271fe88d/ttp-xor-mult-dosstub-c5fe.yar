rule TTP_XOR_MULT_DOSStub_c5fe {
  strings:
    $key_c5fe = { 91 96 [2] e5 8e [2] a2 8c [2] e5 9d [2] ab 91 [2] a7 9b [2] b0 90 [2] ab de [2] 96 }

  condition:
    any of them
}