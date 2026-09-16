rule TTP_XOR_MULT_DOSStub_3f2f {
  strings:
    $key_3f2f = { 6b 47 [2] 1f 5f [2] 58 5d [2] 1f 4c [2] 51 40 [2] 5d 4a [2] 4a 41 [2] 51 0f [2] 6c }

  condition:
    any of them
}