rule TTP_XOR_MULT_DOSStub_3efb {
  strings:
    $key_3efb = { 6a 93 [2] 1e 8b [2] 59 89 [2] 1e 98 [2] 50 94 [2] 5c 9e [2] 4b 95 [2] 50 db [2] 6d }

  condition:
    any of them
}