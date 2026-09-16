rule TTP_XOR_MULT_DOSStub_e8ed {
  strings:
    $key_e8ed = { bc 85 [2] c8 9d [2] 8f 9f [2] c8 8e [2] 86 82 [2] 8a 88 [2] 9d 83 [2] 86 cd [2] bb }

  condition:
    any of them
}