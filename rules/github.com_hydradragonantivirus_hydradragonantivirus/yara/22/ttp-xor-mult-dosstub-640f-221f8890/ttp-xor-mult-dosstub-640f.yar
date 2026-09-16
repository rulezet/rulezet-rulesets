rule TTP_XOR_MULT_DOSStub_640f {
  strings:
    $key_640f = { 30 67 [2] 44 7f [2] 03 7d [2] 44 6c [2] 0a 60 [2] 06 6a [2] 11 61 [2] 0a 2f [2] 37 }

  condition:
    any of them
}