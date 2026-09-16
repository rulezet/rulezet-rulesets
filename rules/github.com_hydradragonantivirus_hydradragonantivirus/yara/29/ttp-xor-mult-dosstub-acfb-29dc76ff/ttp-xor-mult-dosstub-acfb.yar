rule TTP_XOR_MULT_DOSStub_acfb {
  strings:
    $key_acfb = { f8 93 [2] 8c 8b [2] cb 89 [2] 8c 98 [2] c2 94 [2] ce 9e [2] d9 95 [2] c2 db [2] ff }

  condition:
    any of them
}