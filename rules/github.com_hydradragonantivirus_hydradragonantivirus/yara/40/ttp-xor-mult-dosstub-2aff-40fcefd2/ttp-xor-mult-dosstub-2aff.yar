rule TTP_XOR_MULT_DOSStub_2aff {
  strings:
    $key_2aff = { 7e 97 [2] 0a 8f [2] 4d 8d [2] 0a 9c [2] 44 90 [2] 48 9a [2] 5f 91 [2] 44 df [2] 79 }

  condition:
    any of them
}