rule TTP_XOR_MULT_DOSStub_65ed {
  strings:
    $key_65ed = { 31 85 [2] 45 9d [2] 02 9f [2] 45 8e [2] 0b 82 [2] 07 88 [2] 10 83 [2] 0b cd [2] 36 }

  condition:
    any of them
}