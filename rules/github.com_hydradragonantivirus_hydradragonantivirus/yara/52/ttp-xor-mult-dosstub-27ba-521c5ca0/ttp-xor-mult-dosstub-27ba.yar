rule TTP_XOR_MULT_DOSStub_27ba {
  strings:
    $key_27ba = { 73 d2 [2] 07 ca [2] 40 c8 [2] 07 d9 [2] 49 d5 [2] 45 df [2] 52 d4 [2] 49 9a [2] 74 }

  condition:
    any of them
}