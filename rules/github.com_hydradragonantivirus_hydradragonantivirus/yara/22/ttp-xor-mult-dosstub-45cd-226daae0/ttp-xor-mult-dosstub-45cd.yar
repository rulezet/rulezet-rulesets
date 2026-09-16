rule TTP_XOR_MULT_DOSStub_45cd {
  strings:
    $key_45cd = { 11 a5 [2] 65 bd [2] 22 bf [2] 65 ae [2] 2b a2 [2] 27 a8 [2] 30 a3 [2] 2b ed [2] 16 }

  condition:
    any of them
}