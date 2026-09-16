rule TTP_XOR_MULT_DOSStub_297c {
  strings:
    $key_297c = { 7d 14 [2] 09 0c [2] 4e 0e [2] 09 1f [2] 47 13 [2] 4b 19 [2] 5c 12 [2] 47 5c [2] 7a }

  condition:
    any of them
}