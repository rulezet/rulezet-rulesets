rule TTP_XOR_WriteProcessMemory_098d {
  strings:
    $key_098d = { 5e ff [2] 6c dd [2] 6a e8 [2] 44 e8 [2] 7b f4 }

  condition:
    any of them
}