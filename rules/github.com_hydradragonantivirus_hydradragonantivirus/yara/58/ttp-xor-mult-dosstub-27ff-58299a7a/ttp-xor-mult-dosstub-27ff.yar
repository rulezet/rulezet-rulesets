rule TTP_XOR_MULT_DOSStub_27ff {
  strings:
    $key_27ff = { 73 97 [2] 07 8f [2] 40 8d [2] 07 9c [2] 49 90 [2] 45 9a [2] 52 91 [2] 49 df [2] 74 }

  condition:
    any of them
}