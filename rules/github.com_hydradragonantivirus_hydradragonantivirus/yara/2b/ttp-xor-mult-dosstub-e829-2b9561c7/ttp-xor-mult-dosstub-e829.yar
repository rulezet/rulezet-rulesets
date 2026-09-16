rule TTP_XOR_MULT_DOSStub_e829 {
  strings:
    $key_e829 = { bc 41 [2] c8 59 [2] 8f 5b [2] c8 4a [2] 86 46 [2] 8a 4c [2] 9d 47 [2] 86 09 [2] bb }

  condition:
    any of them
}