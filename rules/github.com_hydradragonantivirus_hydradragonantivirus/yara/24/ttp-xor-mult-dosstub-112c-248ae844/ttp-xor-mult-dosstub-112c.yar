rule TTP_XOR_MULT_DOSStub_112c {
  strings:
    $key_112c = { 45 44 [2] 31 5c [2] 76 5e [2] 31 4f [2] 7f 43 [2] 73 49 [2] 64 42 [2] 7f 0c [2] 42 }

  condition:
    any of them
}