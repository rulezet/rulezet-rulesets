rule TTP_XOR_MULT_DOSStub_feb2 {
  strings:
    $key_feb2 = { aa da [2] de c2 [2] 99 c0 [2] de d1 [2] 90 dd [2] 9c d7 [2] 8b dc [2] 90 92 [2] ad }

  condition:
    any of them
}