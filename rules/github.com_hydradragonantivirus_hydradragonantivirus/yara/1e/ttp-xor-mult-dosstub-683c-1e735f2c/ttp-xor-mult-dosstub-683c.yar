rule TTP_XOR_MULT_DOSStub_683c {
  strings:
    $key_683c = { 3c 54 [2] 48 4c [2] 0f 4e [2] 48 5f [2] 06 53 [2] 0a 59 [2] 1d 52 [2] 06 1c [2] 3b }

  condition:
    any of them
}