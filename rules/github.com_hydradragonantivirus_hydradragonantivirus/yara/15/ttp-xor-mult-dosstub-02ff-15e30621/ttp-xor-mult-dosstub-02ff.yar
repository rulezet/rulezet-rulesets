rule TTP_XOR_MULT_DOSStub_02ff {
  strings:
    $key_02ff = { 56 97 [2] 22 8f [2] 65 8d [2] 22 9c [2] 6c 90 [2] 60 9a [2] 77 91 [2] 6c df [2] 51 }

  condition:
    any of them
}