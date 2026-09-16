rule TTP_XOR_MULT_DOSStub_112b {
  strings:
    $key_112b = { 45 43 [2] 31 5b [2] 76 59 [2] 31 48 [2] 7f 44 [2] 73 4e [2] 64 45 [2] 7f 0b [2] 42 }

  condition:
    any of them
}