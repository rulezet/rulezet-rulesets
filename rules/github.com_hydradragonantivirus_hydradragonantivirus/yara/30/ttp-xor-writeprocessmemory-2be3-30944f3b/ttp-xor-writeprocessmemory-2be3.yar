rule TTP_XOR_WriteProcessMemory_2be3 {
  strings:
    $key_2be3 = { 7c 91 [2] 4e b3 [2] 48 86 [2] 66 86 [2] 59 9a }

  condition:
    any of them
}