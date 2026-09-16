rule TTP_XOR_MULT_DOSStub_3f0f {
  strings:
    $key_3f0f = { 6b 67 [2] 1f 7f [2] 58 7d [2] 1f 6c [2] 51 60 [2] 5d 6a [2] 4a 61 [2] 51 2f [2] 6c }

  condition:
    any of them
}