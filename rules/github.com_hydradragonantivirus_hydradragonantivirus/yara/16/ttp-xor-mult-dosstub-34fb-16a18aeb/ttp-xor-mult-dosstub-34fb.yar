rule TTP_XOR_MULT_DOSStub_34fb {
  strings:
    $key_34fb = { 60 93 [2] 14 8b [2] 53 89 [2] 14 98 [2] 5a 94 [2] 56 9e [2] 41 95 [2] 5a db [2] 67 }

  condition:
    any of them
}