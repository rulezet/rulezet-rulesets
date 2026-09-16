rule TTP_XOR_MULT_DOSStub_0aaf {
  strings:
    $key_0aaf = { 5e c7 [2] 2a df [2] 6d dd [2] 2a cc [2] 64 c0 [2] 68 ca [2] 7f c1 [2] 64 8f [2] 59 }

  condition:
    any of them
}