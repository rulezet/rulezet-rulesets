rule TTP_XOR_MULT_DOSStub_abad {
  strings:
    $key_abad = { ff c5 [2] 8b dd [2] cc df [2] 8b ce [2] c5 c2 [2] c9 c8 [2] de c3 [2] c5 8d [2] f8 }

  condition:
    any of them
}