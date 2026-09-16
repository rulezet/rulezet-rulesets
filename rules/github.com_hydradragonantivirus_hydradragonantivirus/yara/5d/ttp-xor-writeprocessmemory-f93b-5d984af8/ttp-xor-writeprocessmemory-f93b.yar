rule TTP_XOR_WriteProcessMemory_f93b {
  strings:
    $key_f93b = { ae 49 [2] 9c 6b [2] 9a 5e [2] b4 5e [2] 8b 42 }

  condition:
    any of them
}