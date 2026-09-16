rule TTP_XOR_MULT_DOSStub_abae {
  strings:
    $key_abae = { ff c6 [2] 8b de [2] cc dc [2] 8b cd [2] c5 c1 [2] c9 cb [2] de c0 [2] c5 8e [2] f8 }

  condition:
    any of them
}