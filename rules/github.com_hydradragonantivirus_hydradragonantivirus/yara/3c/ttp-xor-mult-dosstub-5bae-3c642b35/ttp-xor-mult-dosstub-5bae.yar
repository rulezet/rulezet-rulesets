rule TTP_XOR_MULT_DOSStub_5bae {
  strings:
    $key_5bae = { 0f c6 [2] 7b de [2] 3c dc [2] 7b cd [2] 35 c1 [2] 39 cb [2] 2e c0 [2] 35 8e [2] 08 }

  condition:
    any of them
}