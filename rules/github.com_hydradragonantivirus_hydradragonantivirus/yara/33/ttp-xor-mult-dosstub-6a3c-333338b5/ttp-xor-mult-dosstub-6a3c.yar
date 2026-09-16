rule TTP_XOR_MULT_DOSStub_6a3c {
  strings:
    $key_6a3c = { 3e 54 [2] 4a 4c [2] 0d 4e [2] 4a 5f [2] 04 53 [2] 08 59 [2] 1f 52 [2] 04 1c [2] 39 }

  condition:
    any of them
}