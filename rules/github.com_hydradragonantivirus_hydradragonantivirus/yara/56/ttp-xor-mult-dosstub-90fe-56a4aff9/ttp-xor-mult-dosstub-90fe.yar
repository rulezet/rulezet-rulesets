rule TTP_XOR_MULT_DOSStub_90fe {
  strings:
    $key_90fe = { c4 96 [2] b0 8e [2] f7 8c [2] b0 9d [2] fe 91 [2] f2 9b [2] e5 90 [2] fe de [2] c3 }

  condition:
    any of them
}