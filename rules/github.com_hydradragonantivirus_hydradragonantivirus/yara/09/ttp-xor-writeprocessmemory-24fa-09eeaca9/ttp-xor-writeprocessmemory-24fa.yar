rule TTP_XOR_WriteProcessMemory_24fa {
  strings:
    $key_24fa = { 73 88 [2] 41 aa [2] 47 9f [2] 69 9f [2] 56 83 }

  condition:
    any of them
}