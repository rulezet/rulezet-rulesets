rule TTP_XOR_MULT_DOSStub_653f {
  strings:
    $key_653f = { 31 57 [2] 45 4f [2] 02 4d [2] 45 5c [2] 0b 50 [2] 07 5a [2] 10 51 [2] 0b 1f [2] 36 }

  condition:
    any of them
}