rule TTP_XOR_MULT_DOSStub_6bed {
  strings:
    $key_6bed = { 3f 85 [2] 4b 9d [2] 0c 9f [2] 4b 8e [2] 05 82 [2] 09 88 [2] 1e 83 [2] 05 cd [2] 38 }

  condition:
    any of them
}