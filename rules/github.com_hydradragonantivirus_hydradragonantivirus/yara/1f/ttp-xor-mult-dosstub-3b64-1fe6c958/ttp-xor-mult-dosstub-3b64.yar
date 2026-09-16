rule TTP_XOR_MULT_DOSStub_3b64 {
  strings:
    $key_3b64 = { 6f 0c [2] 1b 14 [2] 5c 16 [2] 1b 07 [2] 55 0b [2] 59 01 [2] 4e 0a [2] 55 44 [2] 68 }

  condition:
    any of them
}