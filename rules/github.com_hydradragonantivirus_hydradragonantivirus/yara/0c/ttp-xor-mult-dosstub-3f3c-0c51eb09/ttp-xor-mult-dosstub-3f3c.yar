rule TTP_XOR_MULT_DOSStub_3f3c {
  strings:
    $key_3f3c = { 6b 54 [2] 1f 4c [2] 58 4e [2] 1f 5f [2] 51 53 [2] 5d 59 [2] 4a 52 [2] 51 1c [2] 6c }

  condition:
    any of them
}