rule TTP_XOR_WriteProcessMemory_281c {
  strings:
    $key_281c = { 7f 6e [2] 4d 4c [2] 4b 79 [2] 65 79 [2] 5a 65 }

  condition:
    any of them
}