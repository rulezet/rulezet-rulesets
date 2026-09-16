rule TTP_XOR_WriteProcessMemory_f89a {
  strings:
    $key_f89a = { af e8 [2] 9d ca [2] 9b ff [2] b5 ff [2] 8a e3 }

  condition:
    any of them
}