rule TTP_XOR_WriteProcessMemory_ffcd {
  strings:
    $key_ffcd = { a8 bf [2] 9a 9d [2] 9c a8 [2] b2 a8 [2] 8d b4 }

  condition:
    any of them
}