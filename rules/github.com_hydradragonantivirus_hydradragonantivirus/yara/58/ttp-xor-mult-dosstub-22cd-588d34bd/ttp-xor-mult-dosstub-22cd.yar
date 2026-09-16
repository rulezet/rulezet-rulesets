rule TTP_XOR_MULT_DOSStub_22cd {
  strings:
    $key_22cd = { 76 a5 [2] 02 bd [2] 45 bf [2] 02 ae [2] 4c a2 [2] 40 a8 [2] 57 a3 [2] 4c ed [2] 71 }

  condition:
    any of them
}