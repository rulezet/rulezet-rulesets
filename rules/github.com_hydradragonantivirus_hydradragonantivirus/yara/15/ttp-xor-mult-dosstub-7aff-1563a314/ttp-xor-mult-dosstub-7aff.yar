rule TTP_XOR_MULT_DOSStub_7aff {
  strings:
    $key_7aff = { 2e 97 [2] 5a 8f [2] 1d 8d [2] 5a 9c [2] 14 90 [2] 18 9a [2] 0f 91 [2] 14 df [2] 29 }

  condition:
    any of them
}