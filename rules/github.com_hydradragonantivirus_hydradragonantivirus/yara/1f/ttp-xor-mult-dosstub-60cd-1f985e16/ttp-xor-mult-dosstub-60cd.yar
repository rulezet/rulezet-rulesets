rule TTP_XOR_MULT_DOSStub_60cd {
  strings:
    $key_60cd = { 34 a5 [2] 40 bd [2] 07 bf [2] 40 ae [2] 0e a2 [2] 02 a8 [2] 15 a3 [2] 0e ed [2] 33 }

  condition:
    any of them
}