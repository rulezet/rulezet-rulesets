rule TTP_XOR_MULT_DOSStub_193c {
  strings:
    $key_193c = { 4d 54 [2] 39 4c [2] 7e 4e [2] 39 5f [2] 77 53 [2] 7b 59 [2] 6c 52 [2] 77 1c [2] 4a }

  condition:
    any of them
}