rule TTP_XOR_MULT_DOSStub_f6ee {
  strings:
    $key_f6ee = { a2 86 [2] d6 9e [2] 91 9c [2] d6 8d [2] 98 81 [2] 94 8b [2] 83 80 [2] 98 ce [2] a5 }

  condition:
    any of them
}