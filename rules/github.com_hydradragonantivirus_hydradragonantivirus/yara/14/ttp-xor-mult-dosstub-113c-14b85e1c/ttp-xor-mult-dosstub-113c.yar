rule TTP_XOR_MULT_DOSStub_113c {
  strings:
    $key_113c = { 45 54 [2] 31 4c [2] 76 4e [2] 31 5f [2] 7f 53 [2] 73 59 [2] 64 52 [2] 7f 1c [2] 42 }

  condition:
    any of them
}