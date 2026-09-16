rule TTP_XOR_MULT_DOSStub_12fc {
  strings:
    $key_12fc = { 46 94 [2] 32 8c [2] 75 8e [2] 32 9f [2] 7c 93 [2] 70 99 [2] 67 92 [2] 7c dc [2] 41 }

  condition:
    any of them
}