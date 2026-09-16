rule TTP_XOR_MULT_DOSStub_a06b {
  strings:
    $key_a06b = { f4 03 [2] 80 1b [2] c7 19 [2] 80 08 [2] ce 04 [2] c2 0e [2] d5 05 [2] ce 4b [2] f3 }

  condition:
    any of them
}