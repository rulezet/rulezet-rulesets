rule TTP_XOR_MULT_DOSStub_5aaf {
  strings:
    $key_5aaf = { 0e c7 [2] 7a df [2] 3d dd [2] 7a cc [2] 34 c0 [2] 38 ca [2] 2f c1 [2] 34 8f [2] 09 }

  condition:
    any of them
}