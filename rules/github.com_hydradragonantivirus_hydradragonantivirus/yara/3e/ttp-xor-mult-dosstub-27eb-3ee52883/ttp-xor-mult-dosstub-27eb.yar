rule TTP_XOR_MULT_DOSStub_27eb {
  strings:
    $key_27eb = { 73 83 [2] 07 9b [2] 40 99 [2] 07 88 [2] 49 84 [2] 45 8e [2] 52 85 [2] 49 cb [2] 74 }

  condition:
    any of them
}