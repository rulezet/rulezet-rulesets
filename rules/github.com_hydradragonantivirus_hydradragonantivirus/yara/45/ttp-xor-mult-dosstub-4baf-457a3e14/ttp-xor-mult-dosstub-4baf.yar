rule TTP_XOR_MULT_DOSStub_4baf {
  strings:
    $key_4baf = { 1f c7 [2] 6b df [2] 2c dd [2] 6b cc [2] 25 c0 [2] 29 ca [2] 3e c1 [2] 25 8f [2] 18 }

  condition:
    any of them
}