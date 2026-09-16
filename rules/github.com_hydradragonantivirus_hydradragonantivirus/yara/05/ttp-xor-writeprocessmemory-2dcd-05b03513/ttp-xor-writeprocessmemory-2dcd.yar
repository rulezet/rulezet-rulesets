rule TTP_XOR_WriteProcessMemory_2dcd {
  strings:
    $key_2dcd = { 7a bf [2] 48 9d [2] 4e a8 [2] 60 a8 [2] 5f b4 }

  condition:
    any of them
}