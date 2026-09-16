rule TTP_XOR_MULT_DOSStub_f723 {
  strings:
    $key_f723 = { a3 4b [2] d7 53 [2] 90 51 [2] d7 40 [2] 99 4c [2] 95 46 [2] 82 4d [2] 99 03 [2] a4 }

  condition:
    any of them
}