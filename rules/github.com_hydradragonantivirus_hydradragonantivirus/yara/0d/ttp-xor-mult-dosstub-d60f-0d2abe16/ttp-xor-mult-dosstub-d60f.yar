rule TTP_XOR_MULT_DOSStub_d60f {
  strings:
    $key_d60f = { 82 67 [2] f6 7f [2] b1 7d [2] f6 6c [2] b8 60 [2] b4 6a [2] a3 61 [2] b8 2f [2] 85 }

  condition:
    any of them
}