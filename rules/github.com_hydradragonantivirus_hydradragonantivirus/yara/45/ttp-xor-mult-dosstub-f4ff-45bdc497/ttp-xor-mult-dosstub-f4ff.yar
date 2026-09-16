rule TTP_XOR_MULT_DOSStub_f4ff {
  strings:
    $key_f4ff = { a0 97 [2] d4 8f [2] 93 8d [2] d4 9c [2] 9a 90 [2] 96 9a [2] 81 91 [2] 9a df [2] a7 }

  condition:
    any of them
}