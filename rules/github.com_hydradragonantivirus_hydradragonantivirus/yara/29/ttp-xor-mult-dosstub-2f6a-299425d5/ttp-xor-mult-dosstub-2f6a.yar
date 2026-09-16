rule TTP_XOR_MULT_DOSStub_2f6a {
  strings:
    $key_2f6a = { 7b 02 [2] 0f 1a [2] 48 18 [2] 0f 09 [2] 41 05 [2] 4d 0f [2] 5a 04 [2] 41 4a [2] 7c }

  condition:
    any of them
}