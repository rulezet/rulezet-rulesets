rule TTP_XOR_MULT_DOSStub_1eed {
  strings:
    $key_1eed = { 4a 85 [2] 3e 9d [2] 79 9f [2] 3e 8e [2] 70 82 [2] 7c 88 [2] 6b 83 [2] 70 cd [2] 4d }

  condition:
    any of them
}