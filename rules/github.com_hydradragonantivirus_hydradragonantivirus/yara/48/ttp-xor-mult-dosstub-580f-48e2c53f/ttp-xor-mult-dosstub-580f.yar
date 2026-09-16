rule TTP_XOR_MULT_DOSStub_580f {
  strings:
    $key_580f = { 0c 67 [2] 78 7f [2] 3f 7d [2] 78 6c [2] 36 60 [2] 3a 6a [2] 2d 61 [2] 36 2f [2] 0b }

  condition:
    any of them
}