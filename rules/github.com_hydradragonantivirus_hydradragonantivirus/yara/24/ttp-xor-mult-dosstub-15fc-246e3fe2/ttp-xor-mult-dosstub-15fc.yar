rule TTP_XOR_MULT_DOSStub_15fc {
  strings:
    $key_15fc = { 41 94 [2] 35 8c [2] 72 8e [2] 35 9f [2] 7b 93 [2] 77 99 [2] 60 92 [2] 7b dc [2] 46 }

  condition:
    any of them
}