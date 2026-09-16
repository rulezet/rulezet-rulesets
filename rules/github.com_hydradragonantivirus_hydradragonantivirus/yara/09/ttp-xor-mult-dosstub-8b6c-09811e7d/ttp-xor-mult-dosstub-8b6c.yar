rule TTP_XOR_MULT_DOSStub_8b6c {
  strings:
    $key_8b6c = { df 04 [2] ab 1c [2] ec 1e [2] ab 0f [2] e5 03 [2] e9 09 [2] fe 02 [2] e5 4c [2] d8 }

  condition:
    any of them
}