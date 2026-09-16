rule TTP_XOR_MULT_DOSStub_bb67 {
  strings:
    $key_bb67 = { ef 0f [2] 9b 17 [2] dc 15 [2] 9b 04 [2] d5 08 [2] d9 02 [2] ce 09 [2] d5 47 [2] e8 }

  condition:
    any of them
}