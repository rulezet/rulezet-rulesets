rule TTP_XOR_MULT_DOSStub_5bec {
  strings:
    $key_5bec = { 0f 84 [2] 7b 9c [2] 3c 9e [2] 7b 8f [2] 35 83 [2] 39 89 [2] 2e 82 [2] 35 cc [2] 08 }

  condition:
    any of them
}