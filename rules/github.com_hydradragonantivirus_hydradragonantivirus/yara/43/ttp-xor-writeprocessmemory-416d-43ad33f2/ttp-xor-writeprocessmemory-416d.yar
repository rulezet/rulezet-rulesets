rule TTP_XOR_WriteProcessMemory_416d {
  strings:
    $key_416d = { 16 1f [2] 24 3d [2] 22 08 [2] 0c 08 [2] 33 14 }

  condition:
    any of them
}