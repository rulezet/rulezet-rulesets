rule TTP_XOR_WriteProcessMemory_798d {
  strings:
    $key_798d = { 2e ff [2] 1c dd [2] 1a e8 [2] 34 e8 [2] 0b f4 }

  condition:
    any of them
}