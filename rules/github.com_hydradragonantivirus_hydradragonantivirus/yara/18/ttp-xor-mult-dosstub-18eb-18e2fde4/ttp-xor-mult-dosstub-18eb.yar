rule TTP_XOR_MULT_DOSStub_18eb {
  strings:
    $key_18eb = { 4c 83 [2] 38 9b [2] 7f 99 [2] 38 88 [2] 76 84 [2] 7a 8e [2] 6d 85 [2] 76 cb [2] 4b }

  condition:
    any of them
}