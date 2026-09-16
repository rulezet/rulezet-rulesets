rule TTP_XOR_WriteProcessMemory_dd8d {
  strings:
    $key_dd8d = { 8a ff [2] b8 dd [2] be e8 [2] 90 e8 [2] af f4 }

  condition:
    any of them
}