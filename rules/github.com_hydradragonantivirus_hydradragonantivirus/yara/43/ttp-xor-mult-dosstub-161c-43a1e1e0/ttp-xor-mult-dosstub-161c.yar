rule TTP_XOR_MULT_DOSStub_161c {
  strings:
    $key_161c = { 42 74 [2] 36 6c [2] 71 6e [2] 36 7f [2] 78 73 [2] 74 79 [2] 63 72 [2] 78 3c [2] 45 }

  condition:
    any of them
}