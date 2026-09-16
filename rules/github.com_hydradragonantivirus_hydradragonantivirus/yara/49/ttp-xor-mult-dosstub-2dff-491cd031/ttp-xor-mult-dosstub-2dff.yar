rule TTP_XOR_MULT_DOSStub_2dff {
  strings:
    $key_2dff = { 79 97 [2] 0d 8f [2] 4a 8d [2] 0d 9c [2] 43 90 [2] 4f 9a [2] 58 91 [2] 43 df [2] 7e }

  condition:
    any of them
}