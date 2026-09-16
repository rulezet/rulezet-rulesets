rule TTP_XOR_MULT_DOSStub_f63c {
  strings:
    $key_f63c = { a2 54 [2] d6 4c [2] 91 4e [2] d6 5f [2] 98 53 [2] 94 59 [2] 83 52 [2] 98 1c [2] a5 }

  condition:
    any of them
}