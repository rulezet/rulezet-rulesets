rule TTP_XOR_MULT_DOSStub_382d {
  strings:
    $key_382d = { 6c 45 [2] 18 5d [2] 5f 5f [2] 18 4e [2] 56 42 [2] 5a 48 [2] 4d 43 [2] 56 0d [2] 6b }

  condition:
    any of them
}