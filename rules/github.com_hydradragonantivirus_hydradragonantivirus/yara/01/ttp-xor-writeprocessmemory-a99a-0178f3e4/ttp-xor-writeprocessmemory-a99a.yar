rule TTP_XOR_WriteProcessMemory_a99a {
  strings:
    $key_a99a = { fe e8 [2] cc ca [2] ca ff [2] e4 ff [2] db e3 }

  condition:
    any of them
}