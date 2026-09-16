rule TTP_XOR_MULT_DOSStub_f735 {
  strings:
    $key_f735 = { a3 5d [2] d7 45 [2] 90 47 [2] d7 56 [2] 99 5a [2] 95 50 [2] 82 5b [2] 99 15 [2] a4 }

  condition:
    any of them
}