rule TTP_XOR_MULT_DOSStub_05cd {
  strings:
    $key_05cd = { 51 a5 [2] 25 bd [2] 62 bf [2] 25 ae [2] 6b a2 [2] 67 a8 [2] 70 a3 [2] 6b ed [2] 56 }

  condition:
    any of them
}