rule TTP_XOR_MULT_DOSStub_d6fe {
  strings:
    $key_d6fe = { 82 96 [2] f6 8e [2] b1 8c [2] f6 9d [2] b8 91 [2] b4 9b [2] a3 90 [2] b8 de [2] 85 }

  condition:
    any of them
}