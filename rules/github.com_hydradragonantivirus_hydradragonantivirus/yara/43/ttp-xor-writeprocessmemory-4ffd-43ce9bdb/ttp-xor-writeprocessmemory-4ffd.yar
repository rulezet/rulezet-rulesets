rule TTP_XOR_WriteProcessMemory_4ffd {
  strings:
    $key_4ffd = { 18 8f [2] 2a ad [2] 2c 98 [2] 02 98 [2] 3d 84 }

  condition:
    any of them
}