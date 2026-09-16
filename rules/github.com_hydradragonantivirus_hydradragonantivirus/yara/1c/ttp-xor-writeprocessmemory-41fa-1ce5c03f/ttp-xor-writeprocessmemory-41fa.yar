rule TTP_XOR_WriteProcessMemory_41fa {
  strings:
    $key_41fa = { 16 88 [2] 24 aa [2] 22 9f [2] 0c 9f [2] 33 83 }

  condition:
    any of them
}