rule TTP_XOR_MULT_DOSStub_8bae {
  strings:
    $key_8bae = { df c6 [2] ab de [2] ec dc [2] ab cd [2] e5 c1 [2] e9 cb [2] fe c0 [2] e5 8e [2] d8 }

  condition:
    any of them
}