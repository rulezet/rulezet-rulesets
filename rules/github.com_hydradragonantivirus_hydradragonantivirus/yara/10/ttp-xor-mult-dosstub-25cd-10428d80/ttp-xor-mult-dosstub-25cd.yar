rule TTP_XOR_MULT_DOSStub_25cd {
  strings:
    $key_25cd = { 71 a5 [2] 05 bd [2] 42 bf [2] 05 ae [2] 4b a2 [2] 47 a8 [2] 50 a3 [2] 4b ed [2] 76 }

  condition:
    any of them
}