rule TTP_XOR_MULT_DOSStub_2beb {
  strings:
    $key_2beb = { 7f 83 [2] 0b 9b [2] 4c 99 [2] 0b 88 [2] 45 84 [2] 49 8e [2] 5e 85 [2] 45 cb [2] 78 }

  condition:
    any of them
}