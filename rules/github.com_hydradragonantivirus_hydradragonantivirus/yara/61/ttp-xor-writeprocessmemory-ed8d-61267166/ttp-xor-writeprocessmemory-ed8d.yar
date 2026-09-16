rule TTP_XOR_WriteProcessMemory_ed8d {
  strings:
    $key_ed8d = { ba ff [2] 88 dd [2] 8e e8 [2] a0 e8 [2] 9f f4 }

  condition:
    any of them
}