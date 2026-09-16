rule TTP_XOR_MULT_DOSStub_28fc {
  strings:
    $key_28fc = { 7c 94 [2] 08 8c [2] 4f 8e [2] 08 9f [2] 46 93 [2] 4a 99 [2] 5d 92 [2] 46 dc [2] 7b }

  condition:
    any of them
}