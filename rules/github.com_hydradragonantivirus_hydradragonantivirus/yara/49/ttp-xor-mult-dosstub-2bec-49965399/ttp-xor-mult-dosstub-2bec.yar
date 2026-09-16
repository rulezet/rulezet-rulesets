rule TTP_XOR_MULT_DOSStub_2bec {
  strings:
    $key_2bec = { 7f 84 [2] 0b 9c [2] 4c 9e [2] 0b 8f [2] 45 83 [2] 49 89 [2] 5e 82 [2] 45 cc [2] 78 }

  condition:
    any of them
}