rule TTP_XOR_MULT_DOSStub_6bfb {
  strings:
    $key_6bfb = { 3f 93 [2] 4b 8b [2] 0c 89 [2] 4b 98 [2] 05 94 [2] 09 9e [2] 1e 95 [2] 05 db [2] 38 }

  condition:
    any of them
}