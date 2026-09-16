rule TTP_XOR_MULT_DOSStub_057c {
  strings:
    $key_057c = { 51 14 [2] 25 0c [2] 62 0e [2] 25 1f [2] 6b 13 [2] 67 19 [2] 70 12 [2] 6b 5c [2] 56 }

  condition:
    any of them
}