rule TTP_XOR_MULT_DOSStub_2ffb {
  strings:
    $key_2ffb = { 7b 93 [2] 0f 8b [2] 48 89 [2] 0f 98 [2] 41 94 [2] 4d 9e [2] 5a 95 [2] 41 db [2] 7c }

  condition:
    any of them
}