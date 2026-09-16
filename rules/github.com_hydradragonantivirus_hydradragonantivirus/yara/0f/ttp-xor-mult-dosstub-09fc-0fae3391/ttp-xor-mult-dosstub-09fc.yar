rule TTP_XOR_MULT_DOSStub_09fc {
  strings:
    $key_09fc = { 5d 94 [2] 29 8c [2] 6e 8e [2] 29 9f [2] 67 93 [2] 6b 99 [2] 7c 92 [2] 67 dc [2] 5a }

  condition:
    any of them
}