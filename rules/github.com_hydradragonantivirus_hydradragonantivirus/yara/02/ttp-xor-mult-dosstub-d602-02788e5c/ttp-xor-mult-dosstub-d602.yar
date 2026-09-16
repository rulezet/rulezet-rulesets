rule TTP_XOR_MULT_DOSStub_d602 {
  strings:
    $key_d602 = { 82 6a [2] f6 72 [2] b1 70 [2] f6 61 [2] b8 6d [2] b4 67 [2] a3 6c [2] b8 22 [2] 85 }

  condition:
    any of them
}