rule TTP_XOR_WriteProcessMemory_e89a {
  strings:
    $key_e89a = { bf e8 [2] 8d ca [2] 8b ff [2] a5 ff [2] 9a e3 }

  condition:
    any of them
}