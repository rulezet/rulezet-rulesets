rule TTP_XOR_MULT_DOSStub_144c {
  strings:
    $key_144c = { 40 24 [2] 34 3c [2] 73 3e [2] 34 2f [2] 7a 23 [2] 76 29 [2] 61 22 [2] 7a 6c [2] 47 }

  condition:
    any of them
}