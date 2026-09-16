rule TTP_XOR_MULT_DOSStub_5dff {
  strings:
    $key_5dff = { 09 97 [2] 7d 8f [2] 3a 8d [2] 7d 9c [2] 33 90 [2] 3f 9a [2] 28 91 [2] 33 df [2] 0e }

  condition:
    any of them
}