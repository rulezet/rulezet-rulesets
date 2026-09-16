rule TTP_XOR_WriteProcessMemory_498d {
  strings:
    $key_498d = { 1e ff [2] 2c dd [2] 2a e8 [2] 04 e8 [2] 3b f4 }

  condition:
    any of them
}