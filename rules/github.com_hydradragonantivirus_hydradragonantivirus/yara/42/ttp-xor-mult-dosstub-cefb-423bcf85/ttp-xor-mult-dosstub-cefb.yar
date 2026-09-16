rule TTP_XOR_MULT_DOSStub_cefb {
  strings:
    $key_cefb = { 9a 93 [2] ee 8b [2] a9 89 [2] ee 98 [2] a0 94 [2] ac 9e [2] bb 95 [2] a0 db [2] 9d }

  condition:
    any of them
}