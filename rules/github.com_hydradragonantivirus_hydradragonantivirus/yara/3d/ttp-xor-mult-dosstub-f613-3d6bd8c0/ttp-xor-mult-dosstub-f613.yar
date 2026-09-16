rule TTP_XOR_MULT_DOSStub_f613 {
  strings:
    $key_f613 = { a2 7b [2] d6 63 [2] 91 61 [2] d6 70 [2] 98 7c [2] 94 76 [2] 83 7d [2] 98 33 [2] a5 }

  condition:
    any of them
}