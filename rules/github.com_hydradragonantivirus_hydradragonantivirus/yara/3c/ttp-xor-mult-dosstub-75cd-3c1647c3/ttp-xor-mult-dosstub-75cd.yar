rule TTP_XOR_MULT_DOSStub_75cd {
  strings:
    $key_75cd = { 21 a5 [2] 55 bd [2] 12 bf [2] 55 ae [2] 1b a2 [2] 17 a8 [2] 00 a3 [2] 1b ed [2] 26 }

  condition:
    any of them
}