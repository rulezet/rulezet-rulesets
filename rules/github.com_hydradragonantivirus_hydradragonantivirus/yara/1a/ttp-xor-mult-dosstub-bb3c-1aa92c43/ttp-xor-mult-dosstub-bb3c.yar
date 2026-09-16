rule TTP_XOR_MULT_DOSStub_bb3c {
  strings:
    $key_bb3c = { ef 54 [2] 9b 4c [2] dc 4e [2] 9b 5f [2] d5 53 [2] d9 59 [2] ce 52 [2] d5 1c [2] e8 }

  condition:
    any of them
}