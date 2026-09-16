rule TTP_XOR_MULT_DOSStub_d2cd {
  strings:
    $key_d2cd = { 86 a5 [2] f2 bd [2] b5 bf [2] f2 ae [2] bc a2 [2] b0 a8 [2] a7 a3 [2] bc ed [2] 81 }

  condition:
    any of them
}