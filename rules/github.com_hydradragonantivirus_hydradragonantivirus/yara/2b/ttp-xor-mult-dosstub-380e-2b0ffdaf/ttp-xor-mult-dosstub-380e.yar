rule TTP_XOR_MULT_DOSStub_380e {
  strings:
    $key_380e = { 6c 66 [2] 18 7e [2] 5f 7c [2] 18 6d [2] 56 61 [2] 5a 6b [2] 4d 60 [2] 56 2e [2] 6b }

  condition:
    any of them
}