rule TTP_XOR_MULT_DOSStub_3f7f {
  strings:
    $key_3f7f = { 6b 17 [2] 1f 0f [2] 58 0d [2] 1f 1c [2] 51 10 [2] 5d 1a [2] 4a 11 [2] 51 5f [2] 6c }

  condition:
    any of them
}