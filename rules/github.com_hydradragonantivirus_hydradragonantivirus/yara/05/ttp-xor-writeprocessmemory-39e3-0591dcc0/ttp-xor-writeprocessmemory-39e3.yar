rule TTP_XOR_WriteProcessMemory_39e3 {
  strings:
    $key_39e3 = { 6e 91 [2] 5c b3 [2] 5a 86 [2] 74 86 [2] 4b 9a }

  condition:
    any of them
}