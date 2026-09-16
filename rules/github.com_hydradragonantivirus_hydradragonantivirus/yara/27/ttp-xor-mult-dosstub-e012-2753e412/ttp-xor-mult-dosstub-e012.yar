rule TTP_XOR_MULT_DOSStub_e012 {
  strings:
    $key_e012 = { b4 7a [2] c0 62 [2] 87 60 [2] c0 71 [2] 8e 7d [2] 82 77 [2] 95 7c [2] 8e 32 [2] b3 }

  condition:
    any of them
}