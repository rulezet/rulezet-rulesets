rule TTP_XOR_MULT_DOSStub_5cec {
  strings:
    $key_5cec = { 08 84 [2] 7c 9c [2] 3b 9e [2] 7c 8f [2] 32 83 [2] 3e 89 [2] 29 82 [2] 32 cc [2] 0f }

  condition:
    any of them
}