rule TTP_XOR_MULT_DOSStub_2f2f {
  strings:
    $key_2f2f = { 7b 47 [2] 0f 5f [2] 48 5d [2] 0f 4c [2] 41 40 [2] 4d 4a [2] 5a 41 [2] 41 0f [2] 7c }

  condition:
    any of them
}