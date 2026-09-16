rule TTP_XOR_MULT_DOSStub_7aae {
  strings:
    $key_7aae = { 2e c6 [2] 5a de [2] 1d dc [2] 5a cd [2] 14 c1 [2] 18 cb [2] 0f c0 [2] 14 8e [2] 29 }

  condition:
    any of them
}