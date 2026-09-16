rule TTP_XOR_MULT_DOSStub_7bae {
  strings:
    $key_7bae = { 2f c6 [2] 5b de [2] 1c dc [2] 5b cd [2] 15 c1 [2] 19 cb [2] 0e c0 [2] 15 8e [2] 28 }

  condition:
    any of them
}