rule TTP_XOR_MULT_DOSStub_37cd {
  strings:
    $key_37cd = { 63 a5 [2] 17 bd [2] 50 bf [2] 17 ae [2] 59 a2 [2] 55 a8 [2] 42 a3 [2] 59 ed [2] 64 }

  condition:
    any of them
}