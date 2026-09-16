rule TTP_XOR_MULT_DOSStub_f624 {
  strings:
    $key_f624 = { a2 4c [2] d6 54 [2] 91 56 [2] d6 47 [2] 98 4b [2] 94 41 [2] 83 4a [2] 98 04 [2] a5 }

  condition:
    any of them
}