rule TTP_XOR_MULT_DOSStub_8baf {
  strings:
    $key_8baf = { df c7 [2] ab df [2] ec dd [2] ab cc [2] e5 c0 [2] e9 ca [2] fe c1 [2] e5 8f [2] d8 }

  condition:
    any of them
}