rule TTP_XOR_MULT_DOSStub_c9ff {
  strings:
    $key_c9ff = { 9d 97 [2] e9 8f [2] ae 8d [2] e9 9c [2] a7 90 [2] ab 9a [2] bc 91 [2] a7 df [2] 9a }

  condition:
    any of them
}