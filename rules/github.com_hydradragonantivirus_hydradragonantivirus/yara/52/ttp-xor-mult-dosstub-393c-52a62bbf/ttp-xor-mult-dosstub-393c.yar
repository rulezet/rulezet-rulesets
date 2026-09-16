rule TTP_XOR_MULT_DOSStub_393c {
  strings:
    $key_393c = { 6d 54 [2] 19 4c [2] 5e 4e [2] 19 5f [2] 57 53 [2] 5b 59 [2] 4c 52 [2] 57 1c [2] 6a }

  condition:
    any of them
}