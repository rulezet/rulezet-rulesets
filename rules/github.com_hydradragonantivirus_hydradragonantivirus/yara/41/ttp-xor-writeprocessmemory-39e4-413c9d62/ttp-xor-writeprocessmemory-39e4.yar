rule TTP_XOR_WriteProcessMemory_39e4 {
  strings:
    $key_39e4 = { 6e 96 [2] 5c b4 [2] 5a 81 [2] 74 81 [2] 4b 9d }

  condition:
    any of them
}