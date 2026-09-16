rule TTP_XOR_MULT_DOSStub_2669 {
  strings:
    $key_2669 = { 72 01 [2] 06 19 [2] 41 1b [2] 06 0a [2] 48 06 [2] 44 0c [2] 53 07 [2] 48 49 [2] 75 }

  condition:
    any of them
}