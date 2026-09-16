rule TTP_XOR_MULT_DOSStub_f1ff {
  strings:
    $key_f1ff = { a5 97 [2] d1 8f [2] 96 8d [2] d1 9c [2] 9f 90 [2] 93 9a [2] 84 91 [2] 9f df [2] a2 }

  condition:
    any of them
}