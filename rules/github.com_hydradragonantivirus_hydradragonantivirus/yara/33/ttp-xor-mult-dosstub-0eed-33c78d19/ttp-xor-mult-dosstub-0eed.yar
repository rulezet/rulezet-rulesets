rule TTP_XOR_MULT_DOSStub_0eed {
  strings:
    $key_0eed = { 5a 85 [2] 2e 9d [2] 69 9f [2] 2e 8e [2] 60 82 [2] 6c 88 [2] 7b 83 [2] 60 cd [2] 5d }

  condition:
    any of them
}