rule TTP_XOR_MULT_DOSStub_5fae {
  strings:
    $key_5fae = { 0b c6 [2] 7f de [2] 38 dc [2] 7f cd [2] 31 c1 [2] 3d cb [2] 2a c0 [2] 31 8e [2] 0c }

  condition:
    any of them
}