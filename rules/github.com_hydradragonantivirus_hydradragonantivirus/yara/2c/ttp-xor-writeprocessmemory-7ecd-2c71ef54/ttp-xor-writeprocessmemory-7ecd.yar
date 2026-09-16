rule TTP_XOR_WriteProcessMemory_7ecd {
  strings:
    $key_7ecd = { 29 bf [2] 1b 9d [2] 1d a8 [2] 33 a8 [2] 0c b4 }

  condition:
    any of them
}