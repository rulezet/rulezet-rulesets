rule TTP_XOR_MULT_DOSStub_3baf {
  strings:
    $key_3baf = { 6f c7 [2] 1b df [2] 5c dd [2] 1b cc [2] 55 c0 [2] 59 ca [2] 4e c1 [2] 55 8f [2] 68 }

  condition:
    any of them
}