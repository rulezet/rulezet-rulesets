rule TTP_XOR_MULT_DOSStub_293b {
  strings:
    $key_293b = { 7d 53 [2] 09 4b [2] 4e 49 [2] 09 58 [2] 47 54 [2] 4b 5e [2] 5c 55 [2] 47 1b [2] 7a }

  condition:
    any of them
}