rule TTP_XOR_MULT_DOSStub_06ff {
  strings:
    $key_06ff = { 52 97 [2] 26 8f [2] 61 8d [2] 26 9c [2] 68 90 [2] 64 9a [2] 73 91 [2] 68 df [2] 55 }

  condition:
    any of them
}