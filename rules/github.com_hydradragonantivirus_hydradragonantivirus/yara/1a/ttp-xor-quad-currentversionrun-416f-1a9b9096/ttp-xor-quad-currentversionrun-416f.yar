rule TTP_XOR_QUAD_CurrentVersionRun_416f {
  strings:
    $key_416f = { 12 00 [2] 36 0e [2] 1d 22 [2] 33 00 [2] 27 1b [2] 28 01 [2] 36 1c [2] 34 1d [2] 2f 1b [2] 33 1c [2] 2f 33 }

  condition:
    any of them
}