rule TTP_XOR_MULT_DOSStub_d61c {
  strings:
    $key_d61c = { 82 74 [2] f6 6c [2] b1 6e [2] f6 7f [2] b8 73 [2] b4 79 [2] a3 72 [2] b8 3c [2] 85 }

  condition:
    any of them
}