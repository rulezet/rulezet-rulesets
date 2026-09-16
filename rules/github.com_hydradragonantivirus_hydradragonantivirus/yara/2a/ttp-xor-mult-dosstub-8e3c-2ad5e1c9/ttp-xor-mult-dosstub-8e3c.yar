rule TTP_XOR_MULT_DOSStub_8e3c {
  strings:
    $key_8e3c = { da 54 [2] ae 4c [2] e9 4e [2] ae 5f [2] e0 53 [2] ec 59 [2] fb 52 [2] e0 1c [2] dd }

  condition:
    any of them
}