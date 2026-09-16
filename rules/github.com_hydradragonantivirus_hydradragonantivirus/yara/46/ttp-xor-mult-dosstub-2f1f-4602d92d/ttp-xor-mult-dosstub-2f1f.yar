rule TTP_XOR_MULT_DOSStub_2f1f {
  strings:
    $key_2f1f = { 7b 77 [2] 0f 6f [2] 48 6d [2] 0f 7c [2] 41 70 [2] 4d 7a [2] 5a 71 [2] 41 3f [2] 7c }

  condition:
    any of them
}