rule TTP_XOR_MULT_DOSStub_f6ff {
  strings:
    $key_f6ff = { a2 97 [2] d6 8f [2] 91 8d [2] d6 9c [2] 98 90 [2] 94 9a [2] 83 91 [2] 98 df [2] a5 }

  condition:
    any of them
}