rule TTP_XOR_WriteProcessMemory_eb9a {
  strings:
    $key_eb9a = { bc e8 [2] 8e ca [2] 88 ff [2] a6 ff [2] 99 e3 }

  condition:
    any of them
}