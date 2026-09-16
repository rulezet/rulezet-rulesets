rule TTP_XOR_WriteProcessMemory_416b {
  strings:
    $key_416b = { 16 19 [2] 24 3b [2] 22 0e [2] 0c 0e [2] 33 12 }

  condition:
    any of them
}