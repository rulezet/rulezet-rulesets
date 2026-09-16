rule TTP_XOR_WriteProcessMemory_048d {
  strings:
    $key_048d = { 53 ff [2] 61 dd [2] 67 e8 [2] 49 e8 [2] 76 f4 }

  condition:
    any of them
}