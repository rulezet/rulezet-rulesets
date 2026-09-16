rule TTP_XOR_MULT_DOSStub_293c {
  strings:
    $key_293c = { 7d 54 [2] 09 4c [2] 4e 4e [2] 09 5f [2] 47 53 [2] 4b 59 [2] 5c 52 [2] 47 1c [2] 7a }

  condition:
    any of them
}