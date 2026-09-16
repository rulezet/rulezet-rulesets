rule TTP_XOR_MULT_DOSStub_63fc {
  strings:
    $key_63fc = { 37 94 [2] 43 8c [2] 04 8e [2] 43 9f [2] 0d 93 [2] 01 99 [2] 16 92 [2] 0d dc [2] 30 }

  condition:
    any of them
}