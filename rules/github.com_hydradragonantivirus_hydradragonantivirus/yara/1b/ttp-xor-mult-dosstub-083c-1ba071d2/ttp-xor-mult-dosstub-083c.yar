rule TTP_XOR_MULT_DOSStub_083c {
  strings:
    $key_083c = { 5c 54 [2] 28 4c [2] 6f 4e [2] 28 5f [2] 66 53 [2] 6a 59 [2] 7d 52 [2] 66 1c [2] 5b }

  condition:
    any of them
}