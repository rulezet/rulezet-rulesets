rule TTP_XOR_MULT_DOSStub_0bae {
  strings:
    $key_0bae = { 5f c6 [2] 2b de [2] 6c dc [2] 2b cd [2] 65 c1 [2] 69 cb [2] 7e c0 [2] 65 8e [2] 58 }

  condition:
    any of them
}