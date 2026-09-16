rule TTP_XOR_MULT_DOSStub_262f {
  strings:
    $key_262f = { 72 47 [2] 06 5f [2] 41 5d [2] 06 4c [2] 48 40 [2] 44 4a [2] 53 41 [2] 48 0f [2] 75 }

  condition:
    any of them
}