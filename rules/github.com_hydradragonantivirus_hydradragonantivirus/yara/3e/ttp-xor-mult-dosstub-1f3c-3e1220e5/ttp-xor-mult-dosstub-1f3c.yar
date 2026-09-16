rule TTP_XOR_MULT_DOSStub_1f3c {
  strings:
    $key_1f3c = { 4b 54 [2] 3f 4c [2] 78 4e [2] 3f 5f [2] 71 53 [2] 7d 59 [2] 6a 52 [2] 71 1c [2] 4c }

  condition:
    any of them
}