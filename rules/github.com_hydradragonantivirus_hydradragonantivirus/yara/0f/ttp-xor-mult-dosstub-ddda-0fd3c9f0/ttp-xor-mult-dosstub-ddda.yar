rule TTP_XOR_MULT_DOSStub_ddda {
  strings:
    $key_ddda = { 89 b2 [2] fd aa [2] ba a8 [2] fd b9 [2] b3 b5 [2] bf bf [2] a8 b4 [2] b3 fa [2] 8e }

  condition:
    any of them
}