rule TTP_XOR_MULT_DOSStub_8e6c {
  strings:
    $key_8e6c = { da 04 [2] ae 1c [2] e9 1e [2] ae 0f [2] e0 03 [2] ec 09 [2] fb 02 [2] e0 4c [2] dd }

  condition:
    any of them
}