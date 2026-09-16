rule TTP_XOR_MULT_DOSStub_7cff {
  strings:
    $key_7cff = { 28 97 [2] 5c 8f [2] 1b 8d [2] 5c 9c [2] 12 90 [2] 1e 9a [2] 09 91 [2] 12 df [2] 2f }

  condition:
    any of them
}