rule TTP_XOR_MULT_DOSStub_267f {
  strings:
    $key_267f = { 72 17 [2] 06 0f [2] 41 0d [2] 06 1c [2] 48 10 [2] 44 1a [2] 53 11 [2] 48 5f [2] 75 }

  condition:
    any of them
}