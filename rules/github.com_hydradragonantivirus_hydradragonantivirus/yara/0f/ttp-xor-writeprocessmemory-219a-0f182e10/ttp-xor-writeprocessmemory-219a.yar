rule TTP_XOR_WriteProcessMemory_219a {
  strings:
    $key_219a = { 76 e8 [2] 44 ca [2] 42 ff [2] 6c ff [2] 53 e3 }

  condition:
    any of them
}