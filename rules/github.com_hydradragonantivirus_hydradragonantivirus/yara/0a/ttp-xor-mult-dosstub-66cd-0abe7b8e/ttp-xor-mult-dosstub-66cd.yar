rule TTP_XOR_MULT_DOSStub_66cd {
  strings:
    $key_66cd = { 32 a5 [2] 46 bd [2] 01 bf [2] 46 ae [2] 08 a2 [2] 04 a8 [2] 13 a3 [2] 08 ed [2] 35 }

  condition:
    any of them
}