rule TTP_XOR_MULT_DOSStub_bb0f {
  strings:
    $key_bb0f = { ef 67 [2] 9b 7f [2] dc 7d [2] 9b 6c [2] d5 60 [2] d9 6a [2] ce 61 [2] d5 2f [2] e8 }

  condition:
    any of them
}