rule TTP_XOR_MULT_DOSStub_3bae {
  strings:
    $key_3bae = { 6f c6 [2] 1b de [2] 5c dc [2] 1b cd [2] 55 c1 [2] 59 cb [2] 4e c0 [2] 55 8e [2] 68 }

  condition:
    any of them
}