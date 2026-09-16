rule TTP_XOR_MULT_DOSStub_00cd {
  strings:
    $key_00cd = { 54 a5 [2] 20 bd [2] 67 bf [2] 20 ae [2] 6e a2 [2] 62 a8 [2] 75 a3 [2] 6e ed [2] 53 }

  condition:
    any of them
}