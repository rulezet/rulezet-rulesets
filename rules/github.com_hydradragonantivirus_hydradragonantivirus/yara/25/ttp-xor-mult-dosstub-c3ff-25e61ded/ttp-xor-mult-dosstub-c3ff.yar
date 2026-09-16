rule TTP_XOR_MULT_DOSStub_c3ff {
  strings:
    $key_c3ff = { 97 97 [2] e3 8f [2] a4 8d [2] e3 9c [2] ad 90 [2] a1 9a [2] b6 91 [2] ad df [2] 90 }

  condition:
    any of them
}