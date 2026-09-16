rule TTP_XOR_MULT_DOSStub_f669 {
  strings:
    $key_f669 = { a2 01 [2] d6 19 [2] 91 1b [2] d6 0a [2] 98 06 [2] 94 0c [2] 83 07 [2] 98 49 [2] a5 }

  condition:
    any of them
}