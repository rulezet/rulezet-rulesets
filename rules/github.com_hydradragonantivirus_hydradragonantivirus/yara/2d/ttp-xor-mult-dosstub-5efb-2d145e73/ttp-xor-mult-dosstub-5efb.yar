rule TTP_XOR_MULT_DOSStub_5efb {
  strings:
    $key_5efb = { 0a 93 [2] 7e 8b [2] 39 89 [2] 7e 98 [2] 30 94 [2] 3c 9e [2] 2b 95 [2] 30 db [2] 0d }

  condition:
    any of them
}