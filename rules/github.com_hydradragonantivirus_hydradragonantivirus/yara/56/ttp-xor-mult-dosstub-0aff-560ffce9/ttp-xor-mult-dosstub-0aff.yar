rule TTP_XOR_MULT_DOSStub_0aff {
  strings:
    $key_0aff = { 5e 97 [2] 2a 8f [2] 6d 8d [2] 2a 9c [2] 64 90 [2] 68 9a [2] 7f 91 [2] 64 df [2] 59 }

  condition:
    any of them
}