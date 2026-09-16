rule TTP_XOR_MULT_DOSStub_8eeb {
  strings:
    $key_8eeb = { da 83 [2] ae 9b [2] e9 99 [2] ae 88 [2] e0 84 [2] ec 8e [2] fb 85 [2] e0 cb [2] dd }

  condition:
    any of them
}