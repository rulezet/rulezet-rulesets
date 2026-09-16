rule TTP_XOR_MULT_DOSStub_09ed {
  strings:
    $key_09ed = { 5d 85 [2] 29 9d [2] 6e 9f [2] 29 8e [2] 67 82 [2] 6b 88 [2] 7c 83 [2] 67 cd [2] 5a }

  condition:
    any of them
}