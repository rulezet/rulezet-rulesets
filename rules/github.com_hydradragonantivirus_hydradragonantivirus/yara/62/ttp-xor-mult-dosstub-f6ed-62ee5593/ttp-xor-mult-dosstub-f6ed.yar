rule TTP_XOR_MULT_DOSStub_f6ed {
  strings:
    $key_f6ed = { a2 85 [2] d6 9d [2] 91 9f [2] d6 8e [2] 98 82 [2] 94 88 [2] 83 83 [2] 98 cd [2] a5 }

  condition:
    any of them
}