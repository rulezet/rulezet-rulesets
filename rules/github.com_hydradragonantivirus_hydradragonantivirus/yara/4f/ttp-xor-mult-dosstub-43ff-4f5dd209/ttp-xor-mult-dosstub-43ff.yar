rule TTP_XOR_MULT_DOSStub_43ff {
  strings:
    $key_43ff = { 17 97 [2] 63 8f [2] 24 8d [2] 63 9c [2] 2d 90 [2] 21 9a [2] 36 91 [2] 2d df [2] 10 }

  condition:
    any of them
}