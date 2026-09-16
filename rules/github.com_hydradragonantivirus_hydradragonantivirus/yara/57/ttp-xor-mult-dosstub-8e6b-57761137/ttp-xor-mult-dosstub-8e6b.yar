rule TTP_XOR_MULT_DOSStub_8e6b {
  strings:
    $key_8e6b = { da 03 [2] ae 1b [2] e9 19 [2] ae 08 [2] e0 04 [2] ec 0e [2] fb 05 [2] e0 4b [2] dd }

  condition:
    any of them
}