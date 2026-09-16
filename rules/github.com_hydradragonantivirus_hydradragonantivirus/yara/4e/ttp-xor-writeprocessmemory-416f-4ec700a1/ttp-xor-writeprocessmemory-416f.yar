rule TTP_XOR_WriteProcessMemory_416f {
  strings:
    $key_416f = { 16 1d [2] 24 3f [2] 22 0a [2] 0c 0a [2] 33 16 }

  condition:
    any of them
}