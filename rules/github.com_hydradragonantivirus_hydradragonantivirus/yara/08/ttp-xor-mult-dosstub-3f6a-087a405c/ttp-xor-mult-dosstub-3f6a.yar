rule TTP_XOR_MULT_DOSStub_3f6a {
  strings:
    $key_3f6a = { 6b 02 [2] 1f 1a [2] 58 18 [2] 1f 09 [2] 51 05 [2] 5d 0f [2] 4a 04 [2] 51 4a [2] 6c }

  condition:
    any of them
}