rule TTP_XOR_MULT_DOSStub_15ed {
  strings:
    $key_15ed = { 41 85 [2] 35 9d [2] 72 9f [2] 35 8e [2] 7b 82 [2] 77 88 [2] 60 83 [2] 7b cd [2] 46 }

  condition:
    any of them
}