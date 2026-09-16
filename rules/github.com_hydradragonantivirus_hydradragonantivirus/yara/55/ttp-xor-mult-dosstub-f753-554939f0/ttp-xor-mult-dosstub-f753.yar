rule TTP_XOR_MULT_DOSStub_f753 {
  strings:
    $key_f753 = { a3 3b [2] d7 23 [2] 90 21 [2] d7 30 [2] 99 3c [2] 95 36 [2] 82 3d [2] 99 73 [2] a4 }

  condition:
    any of them
}