rule TTP_XOR_MULT_DOSStub_3dff {
  strings:
    $key_3dff = { 69 97 [2] 1d 8f [2] 5a 8d [2] 1d 9c [2] 53 90 [2] 5f 9a [2] 48 91 [2] 53 df [2] 6e }

  condition:
    any of them
}