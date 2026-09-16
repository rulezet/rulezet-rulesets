rule TTP_XOR_MULT_DOSStub_dfed {
  strings:
    $key_dfed = { 8b 85 [2] ff 9d [2] b8 9f [2] ff 8e [2] b1 82 [2] bd 88 [2] aa 83 [2] b1 cd [2] 8c }

  condition:
    any of them
}