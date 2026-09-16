rule TTP_XOR_MULT_DOSStub_2fff {
  strings:
    $key_2fff = { 7b 97 [2] 0f 8f [2] 48 8d [2] 0f 9c [2] 41 90 [2] 4d 9a [2] 5a 91 [2] 41 df [2] 7c }

  condition:
    any of them
}