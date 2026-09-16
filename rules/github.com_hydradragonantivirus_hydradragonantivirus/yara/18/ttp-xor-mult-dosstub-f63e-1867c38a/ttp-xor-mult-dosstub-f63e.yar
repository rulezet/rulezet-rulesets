rule TTP_XOR_MULT_DOSStub_f63e {
  strings:
    $key_f63e = { a2 56 [2] d6 4e [2] 91 4c [2] d6 5d [2] 98 51 [2] 94 5b [2] 83 50 [2] 98 1e [2] a5 }

  condition:
    any of them
}