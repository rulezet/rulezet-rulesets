rule TTP_XOR_WriteProcessMemory_6ecd {
  strings:
    $key_6ecd = { 39 bf [2] 0b 9d [2] 0d a8 [2] 23 a8 [2] 1c b4 }

  condition:
    any of them
}