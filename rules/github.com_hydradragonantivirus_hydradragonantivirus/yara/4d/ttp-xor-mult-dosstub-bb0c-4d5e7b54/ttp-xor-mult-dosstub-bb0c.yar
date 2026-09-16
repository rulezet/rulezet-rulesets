rule TTP_XOR_MULT_DOSStub_bb0c {
  strings:
    $key_bb0c = { ef 64 [2] 9b 7c [2] dc 7e [2] 9b 6f [2] d5 63 [2] d9 69 [2] ce 62 [2] d5 2c [2] e8 }

  condition:
    any of them
}