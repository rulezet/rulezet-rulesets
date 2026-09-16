rule TTP_XOR_MULT_DOSStub_3bff {
  strings:
    $key_3bff = { 6f 97 [2] 1b 8f [2] 5c 8d [2] 1b 9c [2] 55 90 [2] 59 9a [2] 4e 91 [2] 55 df [2] 68 }

  condition:
    any of them
}