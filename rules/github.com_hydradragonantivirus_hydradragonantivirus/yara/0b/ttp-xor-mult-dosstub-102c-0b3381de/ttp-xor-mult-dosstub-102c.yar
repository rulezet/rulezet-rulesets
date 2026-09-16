rule TTP_XOR_MULT_DOSStub_102c {
  strings:
    $key_102c = { 44 44 [2] 30 5c [2] 77 5e [2] 30 4f [2] 7e 43 [2] 72 49 [2] 65 42 [2] 7e 0c [2] 43 }

  condition:
    any of them
}