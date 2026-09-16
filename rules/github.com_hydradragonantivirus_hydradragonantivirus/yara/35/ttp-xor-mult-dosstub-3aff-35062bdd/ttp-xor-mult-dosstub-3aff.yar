rule TTP_XOR_MULT_DOSStub_3aff {
  strings:
    $key_3aff = { 6e 97 [2] 1a 8f [2] 5d 8d [2] 1a 9c [2] 54 90 [2] 58 9a [2] 4f 91 [2] 54 df [2] 69 }

  condition:
    any of them
}