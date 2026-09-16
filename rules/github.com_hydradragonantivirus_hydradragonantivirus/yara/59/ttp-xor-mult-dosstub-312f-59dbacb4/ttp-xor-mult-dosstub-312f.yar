rule TTP_XOR_MULT_DOSStub_312f {
  strings:
    $key_312f = { 65 47 [2] 11 5f [2] 56 5d [2] 11 4c [2] 5f 40 [2] 53 4a [2] 44 41 [2] 5f 0f [2] 62 }

  condition:
    any of them
}