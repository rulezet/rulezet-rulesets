rule TTP_XOR_MULT_DOSStub_0fed {
  strings:
    $key_0fed = { 5b 85 [2] 2f 9d [2] 68 9f [2] 2f 8e [2] 61 82 [2] 6d 88 [2] 7a 83 [2] 61 cd [2] 5c }

  condition:
    any of them
}