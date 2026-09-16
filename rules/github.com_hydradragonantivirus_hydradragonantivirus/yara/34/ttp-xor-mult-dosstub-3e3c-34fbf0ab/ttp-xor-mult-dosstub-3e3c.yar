rule TTP_XOR_MULT_DOSStub_3e3c {
  strings:
    $key_3e3c = { 6a 54 [2] 1e 4c [2] 59 4e [2] 1e 5f [2] 50 53 [2] 5c 59 [2] 4b 52 [2] 50 1c [2] 6d }

  condition:
    any of them
}