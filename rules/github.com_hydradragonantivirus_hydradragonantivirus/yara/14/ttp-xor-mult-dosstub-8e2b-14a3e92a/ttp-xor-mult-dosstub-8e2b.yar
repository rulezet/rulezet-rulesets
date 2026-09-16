rule TTP_XOR_MULT_DOSStub_8e2b {
  strings:
    $key_8e2b = { da 43 [2] ae 5b [2] e9 59 [2] ae 48 [2] e0 44 [2] ec 4e [2] fb 45 [2] e0 0b [2] dd }

  condition:
    any of them
}