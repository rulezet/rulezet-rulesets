rule TTP_XOR_MULT_DOSStub_416c {
  strings:
    $key_416c = { 15 04 [2] 61 1c [2] 26 1e [2] 61 0f [2] 2f 03 [2] 23 09 [2] 34 02 [2] 2f 4c [2] 12 }

  condition:
    any of them
}