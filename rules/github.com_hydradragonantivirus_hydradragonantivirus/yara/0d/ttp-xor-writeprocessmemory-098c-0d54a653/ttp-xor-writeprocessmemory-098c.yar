rule TTP_XOR_WriteProcessMemory_098c {
  strings:
    $key_098c = { 5e fe [2] 6c dc [2] 6a e9 [2] 44 e9 [2] 7b f5 }

  condition:
    any of them
}