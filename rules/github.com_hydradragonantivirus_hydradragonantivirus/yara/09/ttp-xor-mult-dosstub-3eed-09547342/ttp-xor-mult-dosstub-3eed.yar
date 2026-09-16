rule TTP_XOR_MULT_DOSStub_3eed {
  strings:
    $key_3eed = { 6a 85 [2] 1e 9d [2] 59 9f [2] 1e 8e [2] 50 82 [2] 5c 88 [2] 4b 83 [2] 50 cd [2] 6d }

  condition:
    any of them
}