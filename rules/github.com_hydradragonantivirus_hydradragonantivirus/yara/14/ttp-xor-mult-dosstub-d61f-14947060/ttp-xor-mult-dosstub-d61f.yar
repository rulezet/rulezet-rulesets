rule TTP_XOR_MULT_DOSStub_d61f {
  strings:
    $key_d61f = { 82 77 [2] f6 6f [2] b1 6d [2] f6 7c [2] b8 70 [2] b4 7a [2] a3 71 [2] b8 3f [2] 85 }

  condition:
    any of them
}