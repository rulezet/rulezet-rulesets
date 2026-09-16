rule TTP_XOR_MULT_DOSStub_d63f {
  strings:
    $key_d63f = { 82 57 [2] f6 4f [2] b1 4d [2] f6 5c [2] b8 50 [2] b4 5a [2] a3 51 [2] b8 1f [2] 85 }

  condition:
    any of them
}