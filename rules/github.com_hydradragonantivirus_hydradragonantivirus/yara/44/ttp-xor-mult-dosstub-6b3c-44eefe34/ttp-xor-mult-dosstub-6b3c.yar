rule TTP_XOR_MULT_DOSStub_6b3c {
  strings:
    $key_6b3c = { 3f 54 [2] 4b 4c [2] 0c 4e [2] 4b 5f [2] 05 53 [2] 09 59 [2] 1e 52 [2] 05 1c [2] 38 }

  condition:
    any of them
}