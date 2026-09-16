rule TTP_XOR_MULT_DOSStub_8e3b {
  strings:
    $key_8e3b = { da 53 [2] ae 4b [2] e9 49 [2] ae 58 [2] e0 54 [2] ec 5e [2] fb 55 [2] e0 1b [2] dd }

  condition:
    any of them
}