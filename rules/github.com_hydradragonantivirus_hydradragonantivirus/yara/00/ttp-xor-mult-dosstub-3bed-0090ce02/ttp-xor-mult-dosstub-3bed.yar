rule TTP_XOR_MULT_DOSStub_3bed {
  strings:
    $key_3bed = { 6f 85 [2] 1b 9d [2] 5c 9f [2] 1b 8e [2] 55 82 [2] 59 88 [2] 4e 83 [2] 55 cd [2] 68 }

  condition:
    any of them
}