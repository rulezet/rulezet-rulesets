rule TTP_XOR_MULT_DOSStub_5bfb {
  strings:
    $key_5bfb = { 0f 93 [2] 7b 8b [2] 3c 89 [2] 7b 98 [2] 35 94 [2] 39 9e [2] 2e 95 [2] 35 db [2] 08 }

  condition:
    any of them
}