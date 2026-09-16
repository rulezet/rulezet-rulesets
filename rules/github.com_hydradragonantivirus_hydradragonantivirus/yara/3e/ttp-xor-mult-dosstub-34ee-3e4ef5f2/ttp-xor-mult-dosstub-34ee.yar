rule TTP_XOR_MULT_DOSStub_34ee {
  strings:
    $key_34ee = { 60 86 [2] 14 9e [2] 53 9c [2] 14 8d [2] 5a 81 [2] 56 8b [2] 41 80 [2] 5a ce [2] 67 }

  condition:
    any of them
}