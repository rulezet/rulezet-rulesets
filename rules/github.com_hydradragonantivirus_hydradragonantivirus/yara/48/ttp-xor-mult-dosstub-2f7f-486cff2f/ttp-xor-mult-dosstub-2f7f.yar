rule TTP_XOR_MULT_DOSStub_2f7f {
  strings:
    $key_2f7f = { 7b 17 [2] 0f 0f [2] 48 0d [2] 0f 1c [2] 41 10 [2] 4d 1a [2] 5a 11 [2] 41 5f [2] 7c }

  condition:
    any of them
}