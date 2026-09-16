rule TTP_XOR_MULT_DOSStub_293d {
  strings:
    $key_293d = { 7d 55 [2] 09 4d [2] 4e 4f [2] 09 5e [2] 47 52 [2] 4b 58 [2] 5c 53 [2] 47 1d [2] 7a }

  condition:
    any of them
}