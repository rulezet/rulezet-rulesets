rule TTP_XOR_MULT_DOSStub_8bed {
  strings:
    $key_8bed = { df 85 [2] ab 9d [2] ec 9f [2] ab 8e [2] e5 82 [2] e9 88 [2] fe 83 [2] e5 cd [2] d8 }

  condition:
    any of them
}