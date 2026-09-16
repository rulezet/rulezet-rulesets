rule TTP_XOR_MULT_DOSStub_077b {
  strings:
    $key_077b = { 53 13 [2] 27 0b [2] 60 09 [2] 27 18 [2] 69 14 [2] 65 1e [2] 72 15 [2] 69 5b [2] 54 }

  condition:
    any of them
}