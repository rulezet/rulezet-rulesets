rule TTP_XOR_MULT_DOSStub_058e {
  strings:
    $key_058e = { 51 e6 [2] 25 fe [2] 62 fc [2] 25 ed [2] 6b e1 [2] 67 eb [2] 70 e0 [2] 6b ae [2] 56 }

  condition:
    any of them
}