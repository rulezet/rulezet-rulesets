rule TTP_XOR_MULT_DOSStub_8eec {
  strings:
    $key_8eec = { da 84 [2] ae 9c [2] e9 9e [2] ae 8f [2] e0 83 [2] ec 89 [2] fb 82 [2] e0 cc [2] dd }

  condition:
    any of them
}