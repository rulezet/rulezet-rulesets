rule TTP_XOR_MULT_DOSStub_2f3f {
  strings:
    $key_2f3f = { 7b 57 [2] 0f 4f [2] 48 4d [2] 0f 5c [2] 41 50 [2] 4d 5a [2] 5a 51 [2] 41 1f [2] 7c }

  condition:
    any of them
}