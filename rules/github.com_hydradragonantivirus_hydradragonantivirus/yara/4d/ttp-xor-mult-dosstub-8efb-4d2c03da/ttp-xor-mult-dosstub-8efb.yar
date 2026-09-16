rule TTP_XOR_MULT_DOSStub_8efb {
  strings:
    $key_8efb = { da 93 [2] ae 8b [2] e9 89 [2] ae 98 [2] e0 94 [2] ec 9e [2] fb 95 [2] e0 db [2] dd }

  condition:
    any of them
}