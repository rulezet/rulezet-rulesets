rule TTP_XOR_MULT_DOSStub_5bff {
  strings:
    $key_5bff = { 0f 97 [2] 7b 8f [2] 3c 8d [2] 7b 9c [2] 35 90 [2] 39 9a [2] 2e 91 [2] 35 df [2] 08 }

  condition:
    any of them
}