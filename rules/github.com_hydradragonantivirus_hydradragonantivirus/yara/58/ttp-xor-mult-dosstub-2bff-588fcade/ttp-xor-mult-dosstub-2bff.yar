rule TTP_XOR_MULT_DOSStub_2bff {
  strings:
    $key_2bff = { 7f 97 [2] 0b 8f [2] 4c 8d [2] 0b 9c [2] 45 90 [2] 49 9a [2] 5e 91 [2] 45 df [2] 78 }

  condition:
    any of them
}