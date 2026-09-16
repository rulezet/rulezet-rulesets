rule TTP_XOR_MULT_DOSStub_c303 {
  strings:
    $key_c303 = { 97 6b [2] e3 73 [2] a4 71 [2] e3 60 [2] ad 6c [2] a1 66 [2] b6 6d [2] ad 23 [2] 90 }

  condition:
    any of them
}