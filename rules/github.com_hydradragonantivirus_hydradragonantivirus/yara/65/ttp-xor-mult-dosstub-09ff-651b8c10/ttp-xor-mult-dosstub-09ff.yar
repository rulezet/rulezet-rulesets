rule TTP_XOR_MULT_DOSStub_09ff {
  strings:
    $key_09ff = { 5d 97 [2] 29 8f [2] 6e 8d [2] 29 9c [2] 67 90 [2] 6b 9a [2] 7c 91 [2] 67 df [2] 5a }

  condition:
    any of them
}