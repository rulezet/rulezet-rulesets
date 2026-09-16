rule TTP_XOR_MULT_DOSStub_077a {
  strings:
    $key_077a = { 53 12 [2] 27 0a [2] 60 08 [2] 27 19 [2] 69 15 [2] 65 1f [2] 72 14 [2] 69 5a [2] 54 }

  condition:
    any of them
}