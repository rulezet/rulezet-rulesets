rule TTP_XOR_MULT_DOSStub_1fae {
  strings:
    $key_1fae = { 4b c6 [2] 3f de [2] 78 dc [2] 3f cd [2] 71 c1 [2] 7d cb [2] 6a c0 [2] 71 8e [2] 4c }

  condition:
    any of them
}