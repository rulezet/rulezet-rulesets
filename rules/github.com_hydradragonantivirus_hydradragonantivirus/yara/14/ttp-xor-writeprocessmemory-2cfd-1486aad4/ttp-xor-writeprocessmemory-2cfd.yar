rule TTP_XOR_WriteProcessMemory_2cfd {
  strings:
    $key_2cfd = { 7b 8f [2] 49 ad [2] 4f 98 [2] 61 98 [2] 5e 84 }

  condition:
    any of them
}