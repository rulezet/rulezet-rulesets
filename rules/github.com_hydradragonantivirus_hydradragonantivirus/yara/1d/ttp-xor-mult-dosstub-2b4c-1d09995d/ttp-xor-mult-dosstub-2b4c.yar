rule TTP_XOR_MULT_DOSStub_2b4c {
  strings:
    $key_2b4c = { 7f 24 [2] 0b 3c [2] 4c 3e [2] 0b 2f [2] 45 23 [2] 49 29 [2] 5e 22 [2] 45 6c [2] 78 }

  condition:
    any of them
}