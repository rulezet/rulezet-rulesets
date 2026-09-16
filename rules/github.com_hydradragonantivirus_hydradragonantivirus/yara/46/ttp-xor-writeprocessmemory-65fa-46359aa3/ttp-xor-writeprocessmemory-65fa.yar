rule TTP_XOR_WriteProcessMemory_65fa {
  strings:
    $key_65fa = { 32 88 [2] 00 aa [2] 06 9f [2] 28 9f [2] 17 83 }

  condition:
    any of them
}