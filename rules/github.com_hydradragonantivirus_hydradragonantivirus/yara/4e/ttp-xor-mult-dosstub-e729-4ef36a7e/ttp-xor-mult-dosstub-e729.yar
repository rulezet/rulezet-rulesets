rule TTP_XOR_MULT_DOSStub_e729 {
  strings:
    $key_e729 = { b3 41 [2] c7 59 [2] 80 5b [2] c7 4a [2] 89 46 [2] 85 4c [2] 92 47 [2] 89 09 [2] b4 }

  condition:
    any of them
}