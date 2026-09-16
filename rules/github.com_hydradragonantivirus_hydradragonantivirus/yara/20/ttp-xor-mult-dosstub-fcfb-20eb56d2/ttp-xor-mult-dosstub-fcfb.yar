rule TTP_XOR_MULT_DOSStub_fcfb {
  strings:
    $key_fcfb = { a8 93 [2] dc 8b [2] 9b 89 [2] dc 98 [2] 92 94 [2] 9e 9e [2] 89 95 [2] 92 db [2] af }

  condition:
    any of them
}