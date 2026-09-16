rule TTP_XOR_MULT_DOSStub_d4cd {
  strings:
    $key_d4cd = { 80 a5 [2] f4 bd [2] b3 bf [2] f4 ae [2] ba a2 [2] b6 a8 [2] a1 a3 [2] ba ed [2] 87 }

  condition:
    any of them
}