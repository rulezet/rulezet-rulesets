rule TTP_XOR_MULT_DOSStub_380f {
  strings:
    $key_380f = { 6c 67 [2] 18 7f [2] 5f 7d [2] 18 6c [2] 56 60 [2] 5a 6a [2] 4d 61 [2] 56 2f [2] 6b }

  condition:
    any of them
}