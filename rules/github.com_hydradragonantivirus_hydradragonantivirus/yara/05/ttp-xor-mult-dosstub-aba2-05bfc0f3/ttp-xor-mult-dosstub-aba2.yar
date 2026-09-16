rule TTP_XOR_MULT_DOSStub_aba2 {
  strings:
    $key_aba2 = { ff ca [2] 8b d2 [2] cc d0 [2] 8b c1 [2] c5 cd [2] c9 c7 [2] de cc [2] c5 82 [2] f8 }

  condition:
    any of them
}