rule TTP_XOR_MULT_DOSStub_1ffb {
  strings:
    $key_1ffb = { 4b 93 [2] 3f 8b [2] 78 89 [2] 3f 98 [2] 71 94 [2] 7d 9e [2] 6a 95 [2] 71 db [2] 4c }

  condition:
    any of them
}