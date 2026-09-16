rule TTP_XOR_WriteProcessMemory_39e8 {
  strings:
    $key_39e8 = { 6e 9a [2] 5c b8 [2] 5a 8d [2] 74 8d [2] 4b 91 }

  condition:
    any of them
}