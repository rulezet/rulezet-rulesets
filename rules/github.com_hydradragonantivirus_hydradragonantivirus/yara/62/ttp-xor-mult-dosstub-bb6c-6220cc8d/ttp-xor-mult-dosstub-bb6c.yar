rule TTP_XOR_MULT_DOSStub_bb6c {
  strings:
    $key_bb6c = { ef 04 [2] 9b 1c [2] dc 1e [2] 9b 0f [2] d5 03 [2] d9 09 [2] ce 02 [2] d5 4c [2] e8 }

  condition:
    any of them
}