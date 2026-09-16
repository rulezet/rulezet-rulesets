rule TTP_XOR_MULT_DOSStub_aca8 {
  strings:
    $key_aca8 = { f8 c0 [2] 8c d8 [2] cb da [2] 8c cb [2] c2 c7 [2] ce cd [2] d9 c6 [2] c2 88 [2] ff }

  condition:
    any of them
}