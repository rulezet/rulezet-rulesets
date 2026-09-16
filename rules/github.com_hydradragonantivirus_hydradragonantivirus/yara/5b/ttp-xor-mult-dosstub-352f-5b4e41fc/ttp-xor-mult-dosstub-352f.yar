rule TTP_XOR_MULT_DOSStub_352f {
  strings:
    $key_352f = { 61 47 [2] 15 5f [2] 52 5d [2] 15 4c [2] 5b 40 [2] 57 4a [2] 40 41 [2] 5b 0f [2] 66 }

  condition:
    any of them
}