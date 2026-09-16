rule TTP_XOR_MULT_DOSStub_2b04 {
  strings:
    $key_2b04 = { 7f 6c [2] 0b 74 [2] 4c 76 [2] 0b 67 [2] 45 6b [2] 49 61 [2] 5e 6a [2] 45 24 [2] 78 }

  condition:
    any of them
}