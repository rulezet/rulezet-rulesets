rule TTP_XOR_WriteProcessMemory_198d {
  strings:
    $key_198d = { 4e ff [2] 7c dd [2] 7a e8 [2] 54 e8 [2] 6b f4 }

  condition:
    any of them
}