rule TTP_XOR_MULT_DOSStub_2bed {
  strings:
    $key_2bed = { 7f 85 [2] 0b 9d [2] 4c 9f [2] 0b 8e [2] 45 82 [2] 49 88 [2] 5e 83 [2] 45 cd [2] 78 }

  condition:
    any of them
}