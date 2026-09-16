rule TTP_XOR_MULT_DOSStub_f633 {
  strings:
    $key_f633 = { a2 5b [2] d6 43 [2] 91 41 [2] d6 50 [2] 98 5c [2] 94 56 [2] 83 5d [2] 98 13 [2] a5 }

  condition:
    any of them
}