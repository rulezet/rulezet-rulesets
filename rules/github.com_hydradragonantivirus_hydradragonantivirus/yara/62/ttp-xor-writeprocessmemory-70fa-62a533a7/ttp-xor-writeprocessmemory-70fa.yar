rule TTP_XOR_WriteProcessMemory_70fa {
  strings:
    $key_70fa = { 27 88 [2] 15 aa [2] 13 9f [2] 3d 9f [2] 02 83 }

  condition:
    any of them
}