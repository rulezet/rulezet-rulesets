rule TTP_XOR_WriteProcessMemory_00fa {
  strings:
    $key_00fa = { 57 88 [2] 65 aa [2] 63 9f [2] 4d 9f [2] 72 83 }

  condition:
    any of them
}