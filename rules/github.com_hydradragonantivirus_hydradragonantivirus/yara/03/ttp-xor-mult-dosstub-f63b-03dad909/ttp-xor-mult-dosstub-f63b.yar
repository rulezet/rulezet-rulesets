rule TTP_XOR_MULT_DOSStub_f63b {
  strings:
    $key_f63b = { a2 53 [2] d6 4b [2] 91 49 [2] d6 58 [2] 98 54 [2] 94 5e [2] 83 55 [2] 98 1b [2] a5 }

  condition:
    any of them
}