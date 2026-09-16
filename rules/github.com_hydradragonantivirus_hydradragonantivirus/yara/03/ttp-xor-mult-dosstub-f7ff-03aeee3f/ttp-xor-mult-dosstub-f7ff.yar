rule TTP_XOR_MULT_DOSStub_f7ff {
  strings:
    $key_f7ff = { a3 97 [2] d7 8f [2] 90 8d [2] d7 9c [2] 99 90 [2] 95 9a [2] 82 91 [2] 99 df [2] a4 }

  condition:
    any of them
}