rule TTP_XOR_MULT_DOSStub_8e3e {
  strings:
    $key_8e3e = { da 56 [2] ae 4e [2] e9 4c [2] ae 5d [2] e0 51 [2] ec 5b [2] fb 50 [2] e0 1e [2] dd }

  condition:
    any of them
}