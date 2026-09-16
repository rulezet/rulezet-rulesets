rule TTP_XOR_WriteProcessMemory_39e2 {
  strings:
    $key_39e2 = { 6e 90 [2] 5c b2 [2] 5a 87 [2] 74 87 [2] 4b 9b }

  condition:
    any of them
}