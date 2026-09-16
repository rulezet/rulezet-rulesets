rule TTP_XOR_MULT_DOSStub_5f0f {
  strings:
    $key_5f0f = { 0b 67 [2] 7f 7f [2] 38 7d [2] 7f 6c [2] 31 60 [2] 3d 6a [2] 2a 61 [2] 31 2f [2] 0c }

  condition:
    any of them
}