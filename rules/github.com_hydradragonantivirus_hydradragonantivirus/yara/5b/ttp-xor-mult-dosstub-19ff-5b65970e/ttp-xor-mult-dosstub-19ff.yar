rule TTP_XOR_MULT_DOSStub_19ff {
  strings:
    $key_19ff = { 4d 97 [2] 39 8f [2] 7e 8d [2] 39 9c [2] 77 90 [2] 7b 9a [2] 6c 91 [2] 77 df [2] 4a }

  condition:
    any of them
}