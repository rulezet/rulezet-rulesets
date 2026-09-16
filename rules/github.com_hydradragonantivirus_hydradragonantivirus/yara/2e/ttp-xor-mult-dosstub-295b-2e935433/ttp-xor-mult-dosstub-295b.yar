rule TTP_XOR_MULT_DOSStub_295b {
  strings:
    $key_295b = { 7d 33 [2] 09 2b [2] 4e 29 [2] 09 38 [2] 47 34 [2] 4b 3e [2] 5c 35 [2] 47 7b [2] 7a }

  condition:
    any of them
}