rule TTP_XOR_MULT_DOSStub_4bae {
  strings:
    $key_4bae = { 1f c6 [2] 6b de [2] 2c dc [2] 6b cd [2] 25 c1 [2] 29 cb [2] 3e c0 [2] 25 8e [2] 18 }

  condition:
    any of them
}