rule TTP_XOR_MULT_DOSStub_f60e {
  strings:
    $key_f60e = { a2 66 [2] d6 7e [2] 91 7c [2] d6 6d [2] 98 61 [2] 94 6b [2] 83 60 [2] 98 2e [2] a5 }

  condition:
    any of them
}