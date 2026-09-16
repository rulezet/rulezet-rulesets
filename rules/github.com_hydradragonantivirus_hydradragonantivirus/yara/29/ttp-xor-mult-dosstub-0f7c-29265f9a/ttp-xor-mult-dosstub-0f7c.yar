rule TTP_XOR_MULT_DOSStub_0f7c {
  strings:
    $key_0f7c = { 5b 14 [2] 2f 0c [2] 68 0e [2] 2f 1f [2] 61 13 [2] 6d 19 [2] 7a 12 [2] 61 5c [2] 5c }

  condition:
    any of them
}