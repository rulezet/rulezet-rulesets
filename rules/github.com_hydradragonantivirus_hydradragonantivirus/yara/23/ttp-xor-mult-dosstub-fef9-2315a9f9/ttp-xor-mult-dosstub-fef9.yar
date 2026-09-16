rule TTP_XOR_MULT_DOSStub_fef9 {
  strings:
    $key_fef9 = { aa 91 [2] de 89 [2] 99 8b [2] de 9a [2] 90 96 [2] 9c 9c [2] 8b 97 [2] 90 d9 [2] ad }

  condition:
    any of them
}