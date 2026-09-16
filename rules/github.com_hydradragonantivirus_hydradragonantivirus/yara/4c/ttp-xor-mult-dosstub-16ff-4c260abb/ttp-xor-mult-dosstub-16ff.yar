rule TTP_XOR_MULT_DOSStub_16ff {
  strings:
    $key_16ff = { 42 97 [2] 36 8f [2] 71 8d [2] 36 9c [2] 78 90 [2] 74 9a [2] 63 91 [2] 78 df [2] 45 }

  condition:
    any of them
}