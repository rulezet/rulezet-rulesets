rule TTP_XOR_MULT_DOSStub_30ea {
  strings:
    $key_30ea = { 64 82 [2] 10 9a [2] 57 98 [2] 10 89 [2] 5e 85 [2] 52 8f [2] 45 84 [2] 5e ca [2] 63 }

  condition:
    any of them
}