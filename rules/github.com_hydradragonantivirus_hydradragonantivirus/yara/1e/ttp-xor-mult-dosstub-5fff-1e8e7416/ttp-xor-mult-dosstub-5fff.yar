rule TTP_XOR_MULT_DOSStub_5fff {
  strings:
    $key_5fff = { 0b 97 [2] 7f 8f [2] 38 8d [2] 7f 9c [2] 31 90 [2] 3d 9a [2] 2a 91 [2] 31 df [2] 0c }

  condition:
    any of them
}