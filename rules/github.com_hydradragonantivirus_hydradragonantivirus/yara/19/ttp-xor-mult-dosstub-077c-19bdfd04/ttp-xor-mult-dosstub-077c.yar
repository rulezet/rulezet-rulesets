rule TTP_XOR_MULT_DOSStub_077c {
  strings:
    $key_077c = { 53 14 [2] 27 0c [2] 60 0e [2] 27 1f [2] 69 13 [2] 65 19 [2] 72 12 [2] 69 5c [2] 54 }

  condition:
    any of them
}