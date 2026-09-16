rule TTP_XOR_MULT_DOSStub_2929 {
  strings:
    $key_2929 = { 7d 41 [2] 09 59 [2] 4e 5b [2] 09 4a [2] 47 46 [2] 4b 4c [2] 5c 47 [2] 47 09 [2] 7a }

  condition:
    any of them
}