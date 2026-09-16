rule TTP_XOR_MULT_DOSStub_3aaf {
  strings:
    $key_3aaf = { 6e c7 [2] 1a df [2] 5d dd [2] 1a cc [2] 54 c0 [2] 58 ca [2] 4f c1 [2] 54 8f [2] 69 }

  condition:
    any of them
}