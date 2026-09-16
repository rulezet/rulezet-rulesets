rule TTP_XOR_MULT_DOSStub_5aff {
  strings:
    $key_5aff = { 0e 97 [2] 7a 8f [2] 3d 8d [2] 7a 9c [2] 34 90 [2] 38 9a [2] 2f 91 [2] 34 df [2] 09 }

  condition:
    any of them
}