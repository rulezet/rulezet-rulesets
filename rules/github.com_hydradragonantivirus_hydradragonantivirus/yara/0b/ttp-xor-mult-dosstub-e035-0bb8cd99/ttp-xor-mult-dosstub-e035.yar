rule TTP_XOR_MULT_DOSStub_e035 {
  strings:
    $key_e035 = { b4 5d [2] c0 45 [2] 87 47 [2] c0 56 [2] 8e 5a [2] 82 50 [2] 95 5b [2] 8e 15 [2] b3 }

  condition:
    any of them
}