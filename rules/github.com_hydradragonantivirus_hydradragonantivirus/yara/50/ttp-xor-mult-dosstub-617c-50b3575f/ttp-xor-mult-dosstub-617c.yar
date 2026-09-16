rule TTP_XOR_MULT_DOSStub_617c {
  strings:
    $key_617c = { 35 14 [2] 41 0c [2] 06 0e [2] 41 1f [2] 0f 13 [2] 03 19 [2] 14 12 [2] 0f 5c [2] 32 }

  condition:
    any of them
}