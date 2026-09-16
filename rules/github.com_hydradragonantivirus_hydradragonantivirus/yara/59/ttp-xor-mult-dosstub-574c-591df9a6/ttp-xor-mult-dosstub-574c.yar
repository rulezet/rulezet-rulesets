rule TTP_XOR_MULT_DOSStub_574c {
  strings:
    $key_574c = { 03 24 [2] 77 3c [2] 30 3e [2] 77 2f [2] 39 23 [2] 35 29 [2] 22 22 [2] 39 6c [2] 04 }

  condition:
    any of them
}