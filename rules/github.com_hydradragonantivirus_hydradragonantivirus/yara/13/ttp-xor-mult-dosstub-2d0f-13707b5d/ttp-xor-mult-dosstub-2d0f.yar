rule TTP_XOR_MULT_DOSStub_2d0f {
  strings:
    $key_2d0f = { 79 67 [2] 0d 7f [2] 4a 7d [2] 0d 6c [2] 43 60 [2] 4f 6a [2] 58 61 [2] 43 2f [2] 7e }

  condition:
    any of them
}