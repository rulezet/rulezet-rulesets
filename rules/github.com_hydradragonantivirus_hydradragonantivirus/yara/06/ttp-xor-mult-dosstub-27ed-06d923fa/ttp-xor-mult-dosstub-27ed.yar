rule TTP_XOR_MULT_DOSStub_27ed {
  strings:
    $key_27ed = { 73 85 [2] 07 9d [2] 40 9f [2] 07 8e [2] 49 82 [2] 45 88 [2] 52 83 [2] 49 cd [2] 74 }

  condition:
    any of them
}