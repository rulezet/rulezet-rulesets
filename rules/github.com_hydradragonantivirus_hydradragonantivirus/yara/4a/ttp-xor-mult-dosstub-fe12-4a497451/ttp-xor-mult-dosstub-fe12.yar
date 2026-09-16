rule TTP_XOR_MULT_DOSStub_fe12 {
  strings:
    $key_fe12 = { aa 7a [2] de 62 [2] 99 60 [2] de 71 [2] 90 7d [2] 9c 77 [2] 8b 7c [2] 90 32 [2] ad }

  condition:
    any of them
}