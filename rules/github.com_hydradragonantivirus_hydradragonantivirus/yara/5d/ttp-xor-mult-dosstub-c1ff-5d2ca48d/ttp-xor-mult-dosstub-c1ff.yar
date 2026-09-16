rule TTP_XOR_MULT_DOSStub_c1ff {
  strings:
    $key_c1ff = { 95 97 [2] e1 8f [2] a6 8d [2] e1 9c [2] af 90 [2] a3 9a [2] b4 91 [2] af df [2] 92 }

  condition:
    any of them
}