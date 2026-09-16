rule TTP_XOR_MULT_DOSStub_0bed {
  strings:
    $key_0bed = { 5f 85 [2] 2b 9d [2] 6c 9f [2] 2b 8e [2] 65 82 [2] 69 88 [2] 7e 83 [2] 65 cd [2] 58 }

  condition:
    any of them
}