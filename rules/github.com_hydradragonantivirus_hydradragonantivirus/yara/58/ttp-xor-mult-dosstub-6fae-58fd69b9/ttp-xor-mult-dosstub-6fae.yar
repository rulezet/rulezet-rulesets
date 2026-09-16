rule TTP_XOR_MULT_DOSStub_6fae {
  strings:
    $key_6fae = { 3b c6 [2] 4f de [2] 08 dc [2] 4f cd [2] 01 c1 [2] 0d cb [2] 1a c0 [2] 01 8e [2] 3c }

  condition:
    any of them
}