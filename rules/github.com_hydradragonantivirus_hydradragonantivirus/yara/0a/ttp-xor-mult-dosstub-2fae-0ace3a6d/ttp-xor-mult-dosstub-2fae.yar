rule TTP_XOR_MULT_DOSStub_2fae {
  strings:
    $key_2fae = { 7b c6 [2] 0f de [2] 48 dc [2] 0f cd [2] 41 c1 [2] 4d cb [2] 5a c0 [2] 41 8e [2] 7c }

  condition:
    any of them
}